use super::*;

#[derive(Clone, Copy, borsh::BorshSerialize, borsh::BorshDeserialize)]
enum ForgeField {
    SelfId,
    Selector,
    PreData,
    EffectData,
}

fn assert_execution_failure<T>(result: &Result<T, LeeError>, expected: &str) {
    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::Execution(error)))
                if error.to_string().contains(expected)
        ),
        "expected an execution rejection containing {expected:?}, got: {:?}",
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
        let post_balance = this.data.native_balance().unwrap() - balance_to_move;
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
            .native_balance(),
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
        Identifier::ZERO,
    );
    let recipient_account_id = AccountId::for_regular_private_account(
        &recipient_keys.npk(),
        &recipient_keys.vpk(),
        Identifier::ZERO,
    );
    let expected_new_commitment_1 = Commitment::new(
        &sender_account_id,
        &Account {
            nonce: sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
            ..Account::funded(
                sender_private_account.data.native_balance().unwrap() - balance_to_move,
            )
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
fn a_journal_claiming_an_unsigned_account_authorized_is_rejected() {
    use crate::validated_state_diff::ValidatedStateDiff;

    let sender_keys = test_public_account_keys_1();
    let recipient_keys = test_private_account_keys_1();
    let state = V03State::new().with_public_account_balances([(sender_keys.account_id(), 100)]);
    let signed = shielded_balance_transfer_for_tests(&sender_keys, &recipient_keys, 10, &state);
    assert!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&signed, &state, 1, 0).is_ok(),
        "the signed transfer must verify"
    );

    // The same proof, which claims the sender authorized it, without the sender's signature.
    let PrivacyPreservingTransaction {
        mut message,
        witness_set,
    } = signed;
    message.nonces.clear();
    let witness_set = WitnessSet::for_message(&message, witness_set.proof, &[]);
    let unsigned = PrivacyPreservingTransaction::new(message, witness_set);

    assert!(matches!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&unsigned, &state, 1, 0),
        Err(LeeError::InvalidPrivacyPreservingProof)
    ));
}

#[test]
fn a_tampered_deferred_effect_is_rejected() {
    use crate::validated_state_diff::ValidatedStateDiff;

    let sender_keys = test_private_account_keys_1();
    let sender_private_account = Account {
        nonce: Nonce(0xdead_beef),
        ..Account::funded(100)
    };
    let recipient_id = test_public_account_keys_1().account_id();
    let state = V03State::new()
        .with_public_account_balances([(recipient_id, 400)])
        .with_private_account(&sender_keys, &sender_private_account);
    let mut tx = deshielded_balance_transfer_for_tests(
        &sender_keys,
        &sender_private_account,
        &recipient_id,
        37,
        &state,
    );
    assert!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0).is_ok(),
        "the unmodified transfer must verify"
    );

    tx.message.public_actions[0].effects[0].data[0] ^= 0xFF;

    assert!(matches!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0),
        Err(LeeError::InvalidPrivacyPreservingProof)
    ));
}

#[test]
fn a_failing_deferred_effect_leaves_the_state_untouched() {
    let program = crate::test_methods::native_spender();
    let program_id = AccountId::from_builtin_program(program.id());
    let sender_keys = test_public_account_keys_1();
    let sender_id = sender_keys.account_id();
    let own_id = AccountId::new([7; 32]);
    let recipient_keys = test_private_account_keys_1();
    let recipient_id = AccountId::for_regular_private_account(
        &recipient_keys.npk(),
        &recipient_keys.vpk(),
        Identifier::ZERO,
    );
    let mut state = V03State::new()
        .with_programs([program.clone()])
        .with_public_account_balances([(sender_id, 10)]);
    let own_data: Vec<u8> = vec![1];
    let overdraft: u128 = 11;

    // Plans cannot read balances, so the overdraft proves and only fails once settled.
    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::new(own_id, program_id),
                ProgramShardSelector::native_balance(sender_id),
                ProgramShardSelector::native_balance(recipient_id),
            ],
            signers: [sender_id].into(),
            private_witnesses: vec![init_witness(&recipient_keys, Identifier::ZERO)],
            instruction_data: Program::serialize_instruction((own_data, overdraft)).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
    )
    .unwrap();
    let message =
        Message::from_circuit_output(vec![state.get_account_by_id(sender_id).nonce], output);
    assert_eq!(
        message
            .public_actions
            .iter()
            .map(|action| action.account_id)
            .collect::<Vec<_>>(),
        vec![own_id, sender_id],
        "the own-shard write must settle before the failing debit"
    );
    let witness_set = WitnessSet::for_message(&message, proof, &[&sender_keys.signing_key]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);
    let public_state = state.public_state.clone();

    let result = state.transition_from_privacy_preserving_transaction(&tx, 1, 0);

    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::NativeTransferFailed(_)
            ))
        ),
        "expected the debit to fail at settlement, got {result:?}"
    );
    assert_eq!(state.public_state, public_state);
    assert!(
        !state
            .private_state
            .1
            .contains(&Nullifier::for_account_initialization(&recipient_id))
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
        let post_balance = this.data.native_balance().unwrap() + balance_to_move;
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
        Identifier::ZERO,
    );
    let expected_new_commitment = Commitment::new(
        &sender_account_id,
        &Account {
            nonce: sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
            ..Account::funded(
                sender_private_account.data.native_balance().unwrap() - balance_to_move,
            )
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
            .native_balance(),
        Ok(recipient_initial_balance + balance_to_move)
    );
}

#[test]
fn a_data_write_on_a_shard_the_executing_program_does_not_own_is_rejected_in_the_circuit() {
    let program = crate::test_methods::data_changer();
    let keys = test_private_account_keys_1();
    let witness = init_witness(&keys, Identifier::ZERO);
    let target_id = witness.account_id();
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
            ProgramShardSelector::native_balance(target_id),
            encode_balance(500).to_vec(),
        ),
    ];

    for (shard, selector, written) in cases {
        let result = execute_and_prove(
            ProvingInput {
                shard_selectors: vec![selector],
                private_witnesses: vec![witness.clone()],
                instruction_data: Program::serialize_instruction(written).unwrap(),
                ..Default::default()
            },
            &synthetic_program(program.clone()),
        );

        assert_execution_failure(&result, "wrote data on a shard selector of");
        assert!(result.is_err(), "writing {shard} must be refused");
    }
}

#[test]
fn data_changer_program_should_fail_for_too_large_data_in_privacy_preserving_circuit() {
    let program = crate::test_methods::data_changer();
    let program_id = AccountId::from_builtin_program(program.id());
    let keys = test_private_account_keys_1();
    let witness = init_witness(&keys, Identifier::ZERO);
    let account_id = witness.account_id();

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
            private_witnesses: vec![witness],
            instruction_data: Program::serialize_instruction(large_data).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
    );

    assert_program_prove_failure(&result, "written data fits the data limit");
}

#[test]
fn unauthorized_debit_is_refused_when_proving() {
    let sender_id = AccountId::new([0; 32]);
    let recipient_id = AccountId::new([1; 32]);

    let result = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::native_balance(sender_id),
                ProgramShardSelector::native_balance(recipient_id),
            ],
            signers: [recipient_id].into(),
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
                    TransferError::UnauthorizedSender { account_id }
                )
            )) if account_id == sender_id
        ),
        "expected an unauthorized sender rejection"
    );
}

#[test]
fn two_deshielded_transfers_to_one_recipient_compose_at_settlement() {
    let recipient_id = test_public_account_keys_1().account_id();
    let senders = [
        (test_private_account_keys_1(), 37_u128),
        (test_private_account_keys_2(), 11),
    ];
    let sender_account = Account {
        nonce: Nonce(0xdead_beef),
        ..Account::funded(100)
    };

    let mut state = V03State::new().with_public_account_balances([(recipient_id, 400)]);
    for (keys, _) in &senders {
        state = state.with_private_account(keys, &sender_account);
    }

    let transactions: Vec<_> = senders
        .iter()
        .map(|(keys, amount)| {
            deshielded_balance_transfer_for_tests(
                keys,
                &sender_account,
                &recipient_id,
                *amount,
                &state,
            )
        })
        .collect();

    let mut expected = 400;
    for (tx, (_, amount)) in transactions.iter().zip(&senders) {
        state
            .transition_from_privacy_preserving_transaction(tx, 1, 0)
            .unwrap();
        expected += amount;
        assert_eq!(
            state.get_account_by_id(recipient_id).data.native_balance(),
            Ok(expected)
        );
    }
}

#[test]
fn a_guest_evaluated_public_effect_settles_against_live_state() {
    let program = crate::test_methods::native_spender();
    let program_id = AccountId::from_builtin_program(program.id());
    let sender_keys = test_private_account_keys_1();
    let sender_id = AccountId::for_regular_private_account(
        &sender_keys.npk(),
        &sender_keys.vpk(),
        Identifier::ZERO,
    );
    let written_to = AccountId::new([77; 32]);
    let recipient_id = AccountId::new([88; 32]);
    let amount: u128 = 30;

    let pre_account = Account::funded(100);
    let mut state = V03State::new()
        .with_test_programs()
        .with_private_account(&sender_keys, &pre_account);
    let membership_proof = state
        .get_proof_for_commitment(&Commitment::new(&sender_id, &pre_account))
        .expect("the account's commitment must be in state");

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                // A public account whose shard belongs to the guest, so the guest evaluates the
                // effect on it.
                ProgramShardSelector::new(written_to, program_id),
                ProgramShardSelector::native_balance(sender_id),
                ProgramShardSelector::native_balance(recipient_id),
            ],
            private_witnesses: vec![update_witness(
                &sender_keys,
                Identifier::ZERO,
                pre_account,
                membership_proof,
            )],
            instruction_data: Program::serialize_instruction((vec![5_u8; 4], amount)).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
    )
    .unwrap();

    let message = Message::from_circuit_output(vec![], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .expect("a guest-evaluated public effect settles");

    // The guest's own shard was written by its apply, not by a pinned post-state.
    assert_eq!(
        state
            .get_account_by_id(written_to)
            .data
            .shard(program_id)
            .as_ref(),
        &[5_u8; 4]
    );
    // The native leg of the same transaction settled alongside it.
    assert_eq!(
        state.get_account_by_id(recipient_id).data.native_balance(),
        Ok(amount)
    );
}

fn assert_forged_field_is_refused(forge_field: ForgeField) {
    let program = crate::test_methods::forges_apply_echo();
    let program_id = AccountId::from_builtin_program(program.id());
    let sender_keys = test_private_account_keys_1();
    let sender_id = AccountId::for_regular_private_account(
        &sender_keys.npk(),
        &sender_keys.vpk(),
        Identifier::ZERO,
    );
    let written_to = AccountId::new([77; 32]);

    let pre_account = Account::funded(100);
    let mut state = V03State::new()
        .with_test_programs()
        .with_private_account(&sender_keys, &pre_account);
    let membership_proof = state
        .get_proof_for_commitment(&Commitment::new(&sender_id, &pre_account))
        .expect("the account's commitment must be in state");

    let (output, proof) = execute_and_prove(
        ProvingInput {
            shard_selectors: vec![
                ProgramShardSelector::new(written_to, program_id),
                ProgramShardSelector::native_balance(sender_id),
                ProgramShardSelector::native_balance(AccountId::new([88; 32])),
            ],
            private_witnesses: vec![update_witness(
                &sender_keys,
                Identifier::ZERO,
                pre_account,
                membership_proof,
            )],
            instruction_data: Program::serialize_instruction((forge_field, 30_u128)).unwrap(),
            ..Default::default()
        },
        &synthetic_program(program),
    )
    .unwrap();

    let message = Message::from_circuit_output(vec![], output);
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    let result = state.transition_from_privacy_preserving_transaction(&tx, 1, 0);

    assert!(
        matches!(
            &result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::Execution(ExecutionError::ExecutionValidation {
                    source: ExecutionValidationError::ApplyInputMismatch { .. },
                    ..
                })
            ))
        ),
        "expected the echo binding to refuse the forged apply output, got {result:?}"
    );
    // Neither the forged balance nor the effect the proof actually recorded lands.
    assert_eq!(state.get_account_by_id(written_to), Account::default());
}

#[test]
fn an_apply_forging_its_own_account_id_is_refused() {
    assert_forged_field_is_refused(ForgeField::SelfId);
}

#[test]
fn an_apply_forging_the_applied_selector_is_refused() {
    assert_forged_field_is_refused(ForgeField::Selector);
}

#[test]
fn an_apply_forging_the_pre_state_it_was_given_is_refused() {
    assert_forged_field_is_refused(ForgeField::PreData);
}

#[test]
fn an_apply_forging_the_effect_it_actually_planned_is_refused() {
    assert_forged_field_is_refused(ForgeField::EffectData);
}

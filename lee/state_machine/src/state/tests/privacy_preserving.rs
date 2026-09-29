use super::*;

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
    let unsigned = PrivacyPreservingTransaction::new(
        message.clone(),
        WitnessSet::for_message(&message, witness_set.proof.clone(), &[]),
    );

    assert!(matches!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&unsigned, &state, 1, 0),
        Err(LeeError::InvalidInput(msg)) if msg == "Authorized accounts do not match the signers"
    ));

    // Dropping the claim to match the missing signature detaches the statement from its proof.
    message.declared.authorized_accounts.clear();
    let unclaimed = PrivacyPreservingTransaction::new(
        message.clone(),
        WitnessSet::for_message(&message, witness_set.proof, &[]),
    );

    assert!(matches!(
        ValidatedStateDiff::from_privacy_preserving_transaction(&unclaimed, &state, 1, 0),
        Err(LeeError::InvalidPrivacyPreservingProof)
    ));
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

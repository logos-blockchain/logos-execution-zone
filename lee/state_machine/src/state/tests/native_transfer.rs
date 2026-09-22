use super::*;

#[test]
fn transition_from_native_transfer_invocation_credits_empty_and_funded_recipients() {
    let from_key = PrivateKey::try_new([1; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));

    for (recipient_balance, amount) in [(0, 5), (100, 8)] {
        let mut state = V03State::new().with_public_accounts([
            (from, Account::funded(200)),
            (to, Account::funded(recipient_balance)),
        ]);
        assert_eq!(
            state.get_account_by_id(to) == Account::default(),
            recipient_balance == 0
        );

        let tx = transfer_transaction(from, &from_key, 0, to, &to_key, 0, amount);
        state.transition_from_public_transaction(&tx, 1, 0).unwrap();

        assert_eq!(
            state.get_account_by_id(from).data.balance(),
            Ok(200 - amount)
        );
        assert_eq!(
            state.get_account_by_id(to).data.balance(),
            Ok(recipient_balance + amount)
        );
        assert_eq!(state.get_account_by_id(from).nonce, Nonce(1));
        assert_eq!(state.get_account_by_id(to).nonce, Nonce(1));
    }
}

#[test]
fn transition_from_sequence_of_native_transfer_invocations() {
    let key1 = PrivateKey::try_new([8; 32]).unwrap();
    let account_id1 = AccountId::from(&PublicKey::new_from_private_key(&key1));
    let key2 = PrivateKey::try_new([2; 32]).unwrap();
    let account_id2 = AccountId::from(&PublicKey::new_from_private_key(&key2));
    let initial_data = [(account_id1, Account::funded(100))];
    let mut state = V03State::new().with_public_accounts(initial_data);
    let key3 = PrivateKey::try_new([3; 32]).unwrap();
    let account_id3 = AccountId::from(&PublicKey::new_from_private_key(&key3));
    let balance_to_move = 5;

    let tx = transfer_transaction(
        account_id1,
        &key1,
        0,
        account_id2,
        &key2,
        0,
        balance_to_move,
    );
    state.transition_from_public_transaction(&tx, 1, 0).unwrap();
    let balance_to_move = 3;
    let tx = transfer_transaction(
        account_id2,
        &key2,
        1,
        account_id3,
        &key3,
        0,
        balance_to_move,
    );
    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(state.get_account_by_id(account_id1).data.balance(), Ok(95));
    assert_eq!(state.get_account_by_id(account_id2).data.balance(), Ok(2));
    assert_eq!(state.get_account_by_id(account_id3).data.balance(), Ok(3));
    assert_eq!(state.get_account_by_id(account_id1).nonce, Nonce(1));
    assert_eq!(state.get_account_by_id(account_id2).nonce, Nonce(2));
    assert_eq!(state.get_account_by_id(account_id3).nonce, Nonce(1));
}

#[test]
fn a_guest_writes_its_own_shard_and_chains_a_transfer_of_the_same_account() {
    let program = crate::test_methods::native_spender();
    let program_id = AccountId::from_builtin_program(program.id());
    let stranger = AccountId::new([9; 32]);
    let stranger_record: ShardData = b"untouched".to_vec().try_into().unwrap();

    let sender_key = PrivateKey::try_new([11; 32]).unwrap();
    let sender = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
    let recipient = AccountId::new([12; 32]);
    let written: Vec<u8> = vec![7; 4];
    let amount: u128 = 30;

    let mut state = V03State::new()
        .with_public_accounts([(
            sender,
            Account::funded(100).with_shard(stranger, stranger_record.clone()),
        )])
        .with_test_programs();

    let message = public_transaction::Message::try_new(
        program_id,
        vec![
            ProgramShardSelector::new(sender, program_id),
            ProgramShardSelector::balance(sender),
            ProgramShardSelector::balance(recipient),
        ],
        vec![Nonce(0)],
        (written.clone(), amount),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&sender_key]);

    state
        .transition_from_public_transaction(&PublicTransaction::new(message, witness_set), 1, 0)
        .unwrap();

    let sender_post = state.get_account_by_id(sender);
    assert_eq!(sender_post.data.shard(program_id).as_ref(), written);
    assert_eq!(sender_post.data.balance(), Ok(70));
    assert_eq!(sender_post.data.shard(stranger), &stranger_record);
    assert_eq!(sender_post.nonce, Nonce(1));
    assert_eq!(state.get_account_by_id(recipient).data.balance(), Ok(30));
}

#[test]
fn a_repeated_shard_selector_is_rejected() {
    let account_id = AccountId::new([4; 32]);
    let mut state = V03State::new();

    let message = public_transaction::Message::try_new(
        NATIVE_TOKEN_PROGRAM_ID,
        vec![
            ProgramShardSelector::balance(account_id),
            ProgramShardSelector::balance(account_id),
        ],
        vec![],
        NativeInstruction::Transfer { amount: 0 },
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);

    let result = state.transition_from_public_transaction(
        &PublicTransaction::new(message, witness_set),
        1,
        0,
    );

    let Err(LeeError::InvalidInput(message)) = result else {
        panic!("a duplicate pair was accepted: {result:?}");
    };
    assert!(message.contains("Duplicate shard selectors"), "{message}");
}

#[test]
fn a_guest_cannot_write_the_native_shard_publicly() {
    let target_id = AccountId::new([1; 32]);
    let mut state = V03State::new().with_test_programs();
    let program_id = AccountId::from_builtin_program(crate::test_methods::data_changer().id());

    let message = public_transaction::Message::try_new(
        program_id,
        vec![ProgramShardSelector::balance(target_id)],
        vec![],
        encode_balance(500).to_vec(),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);

    let result = state.transition_from_public_transaction(
        &PublicTransaction::new(message, witness_set),
        1,
        0,
    );

    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::ExecutionValidationFailed(
                    ExecutionValidationError::ForeignShardWrite { account_id, .. }
                )
            )) if account_id == target_id
        ),
        "a guest wrote the native shard: {result:?}"
    );
    assert_eq!(state.get_account_by_id(target_id), Account::default());
}

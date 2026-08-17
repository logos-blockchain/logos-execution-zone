use super::*;

#[test]
fn transition_from_authenticated_transfer_program_invocation_default_account_destination() {
    let key = PrivateKey::try_new([1; 32]).unwrap();
    let account_id = AccountId::from(&PublicKey::new_from_private_key(&key));
    let initial_data = [(
        account_id,
        Account {
            program_owner: crate::test_methods::simple_balance_transfer().id(),
            balance: 100,
            ..Account::default()
        },
    )];
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs();
    let from = account_id;
    let to_key = PrivateKey::try_new([2; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));
    assert_eq!(state.get_account_by_id(to), Account::default());
    let balance_to_move = 5;

    let tx = transfer_transaction(from, &key, 0, to, &to_key, 0, balance_to_move);
    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(state.get_account_by_id(from).balance, 95);
    assert_eq!(state.get_account_by_id(to).balance, 5);
    assert_eq!(state.get_account_by_id(from).nonce, Nonce(1));
    assert_eq!(state.get_account_by_id(to).nonce, Nonce(1));
}

#[test]
fn transition_from_authenticated_transfer_program_invocation_insuficient_balance() {
    let key = PrivateKey::try_new([1; 32]).unwrap();
    let account_id = AccountId::from(&PublicKey::new_from_private_key(&key));
    // Owned by the executing program (matching the other tests in this file): otherwise the
    // diff-native ownership check (`UnauthorizedBalanceDecrease`) rejects the balance decrease
    // before `apply_balance_diff` ever gets a chance to reject it for being insufficient, which
    // isn't what this test means to exercise.
    let initial_data = [(
        account_id,
        Account {
            program_owner: crate::test_methods::simple_balance_transfer().id(),
            balance: 100,
            ..Account::default()
        },
    )];
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs();
    let from = account_id;
    let from_key = key;
    let to_key = PrivateKey::try_new([2; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));
    let balance_to_move = 101;
    assert!(state.get_account_by_id(from).balance < balance_to_move);

    let tx = transfer_transaction(from, &from_key, 0, to, &to_key, 0, balance_to_move);
    let result = state.transition_from_public_transaction(&tx, 1, 0);

    // Balance-sufficiency is no longer checked in-guest — `authenticated_transfer` emits a
    // plain `BalanceDiff::Sub` and lets `apply_balance_diff`'s checked arithmetic (applied
    // unconditionally to every diff, at the protocol level) reject an insufficient balance.
    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::BalanceDiffFailed(_)
        ))
    ));
    assert_eq!(state.get_account_by_id(from).balance, 100);
    assert_eq!(state.get_account_by_id(to).balance, 0);
    assert_eq!(state.get_account_by_id(from).nonce, Nonce(0));
    assert_eq!(state.get_account_by_id(to).nonce, Nonce(0));
}

#[test]
fn transition_from_authenticated_transfer_program_invocation_non_default_account_destination() {
    let key1 = PrivateKey::try_new([1; 32]).unwrap();
    let key2 = PrivateKey::try_new([2; 32]).unwrap();
    let account_id1 = AccountId::from(&PublicKey::new_from_private_key(&key1));
    let account_id2 = AccountId::from(&PublicKey::new_from_private_key(&key2));
    let initial_data = [
        (
            account_id1,
            Account {
                program_owner: crate::test_methods::simple_balance_transfer().id(),
                balance: 100,
                ..Account::default()
            },
        ),
        (
            account_id2,
            Account {
                program_owner: crate::test_methods::simple_balance_transfer().id(),
                balance: 200,
                ..Account::default()
            },
        ),
    ];
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs();
    let from = account_id2;
    let from_key = key2;
    let to = account_id1;
    let to_key = key1;
    assert_ne!(state.get_account_by_id(to), Account::default());
    let balance_to_move = 8;

    let tx = transfer_transaction(from, &from_key, 0, to, &to_key, 0, balance_to_move);
    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(state.get_account_by_id(from).balance, 192);
    assert_eq!(state.get_account_by_id(to).balance, 108);
    assert_eq!(state.get_account_by_id(from).nonce, Nonce(1));
    assert_eq!(state.get_account_by_id(to).nonce, Nonce(1));
}

#[test]
fn transition_from_sequence_of_authenticated_transfer_program_invocations() {
    let key1 = PrivateKey::try_new([8; 32]).unwrap();
    let account_id1 = AccountId::from(&PublicKey::new_from_private_key(&key1));
    let key2 = PrivateKey::try_new([2; 32]).unwrap();
    let account_id2 = AccountId::from(&PublicKey::new_from_private_key(&key2));
    let initial_data = [(
        account_id1,
        Account {
            program_owner: crate::test_methods::simple_balance_transfer().id(),
            balance: 100,
            ..Account::default()
        },
    )];
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs();
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

    assert_eq!(state.get_account_by_id(account_id1).balance, 95);
    assert_eq!(state.get_account_by_id(account_id2).balance, 2);
    assert_eq!(state.get_account_by_id(account_id3).balance, 3);
    assert_eq!(state.get_account_by_id(account_id1).nonce, Nonce(1));
    assert_eq!(state.get_account_by_id(account_id2).nonce, Nonce(2));
    assert_eq!(state.get_account_by_id(account_id3).nonce, Nonce(1));
}

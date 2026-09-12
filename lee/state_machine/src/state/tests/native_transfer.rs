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

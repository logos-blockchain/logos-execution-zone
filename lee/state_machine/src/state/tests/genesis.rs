use super::*;

#[test]
fn new_works() {
    let key1 = PrivateKey::try_new([1; 32]).unwrap();
    let key2 = PrivateKey::try_new([2; 32]).unwrap();
    let addr1 = AccountId::from(&PublicKey::new_from_private_key(&key1));
    let addr2 = AccountId::from(&PublicKey::new_from_private_key(&key2));
    let native = crate::test_methods::simple_balance_transfer().id();
    let expected_public_state = {
        let mut this = HashMap::new();
        this.insert(
            addr1,
            Account::single(native, 100, Data::default(), Nonce::default()),
        );
        this.insert(
            addr2,
            Account::single(native, 151, Data::default(), Nonce::default()),
        );
        this
    };
    let state = V03State::new()
        .with_public_account_balances(native, [(addr1, 100_u128), (addr2, 151_u128)]);

    assert_eq!(state.public_state, expected_public_state);
}

#[test]
fn new_includes_nullifiers_for_private_accounts() {
    let keys1 = test_private_account_keys_1();
    let keys2 = test_private_account_keys_2();

    let account = Account::single(
        crate::test_methods::simple_balance_transfer().id(),
        100,
        Data::default(),
        Nonce::default(),
    );

    let account_id1 = AccountId::for_regular_private_account(&keys1.npk(), &keys1.vpk(), 0);
    let account_id2 = AccountId::for_regular_private_account(&keys2.npk(), &keys2.vpk(), 0);

    let init_commitment1 = Commitment::new(&account_id1, &account);
    let init_commitment2 = Commitment::new(&account_id2, &account);
    let init_nullifier1 = Nullifier::for_account_initialization(&account_id1);
    let init_nullifier2 = Nullifier::for_account_initialization(&account_id2);

    let initial_private_accounts = vec![
        (init_commitment1, init_nullifier1),
        (init_commitment2, init_nullifier2),
    ];

    let state = V03State::new().with_private_accounts(initial_private_accounts);

    assert!(state.private_state.1.contains(&init_nullifier1));
    assert!(state.private_state.1.contains(&init_nullifier2));
}

#[test]
fn insert_program() {
    let mut state = V03State::new();
    let program_to_insert = crate::test_methods::simple_balance_transfer();
    let program_id = program_to_insert.id();
    let account_id = lee_core::account::AccountId::from(program_id);
    assert!(!state.public_state.contains_key(&account_id));

    state.insert_program(&program_to_insert);

    assert!(state.public_state.contains_key(&account_id));
}

#[test]
fn get_account_by_account_id_non_default_account() {
    let key = PrivateKey::try_new([1; 32]).unwrap();
    let account_id = AccountId::from(&PublicKey::new_from_private_key(&key));
    let initial_data = [(
        account_id,
        Account::single(
            crate::test_methods::simple_balance_transfer().id(),
            100,
            Data::default(),
            Nonce::default(),
        ),
    )];
    let state = V03State::new().with_public_accounts(initial_data);
    let expected_account = &state.public_state[&account_id];

    let account = state.get_account_by_id(account_id);

    assert_eq!(&account, expected_account);
}

#[test]
fn get_account_by_account_id_default_account() {
    let addr2 = AccountId::new([0; 32]);
    let state = V03State::new();
    let expected_account = Account::default();

    let account = state.get_account_by_id(addr2);

    assert_eq!(account, expected_account);
}

#[test]
fn state_serialization_roundtrip() {
    let account_id_1 = AccountId::new([1; 32]);
    let account_id_2 = AccountId::new([2; 32]);
    let initial_data = [(account_id_1, 100_u128), (account_id_2, 151_u128)];
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&initial_data))
        .with_test_programs();
    let bytes = borsh::to_vec(&state).unwrap();
    let state_from_bytes: V03State = borsh::from_slice(&bytes).unwrap();
    assert_eq!(state, state_from_bytes);
}

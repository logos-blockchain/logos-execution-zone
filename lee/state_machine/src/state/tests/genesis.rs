use super::*;

#[test]
fn new_works() {
    let key1 = PrivateKey::try_new([1; 32]).unwrap();
    let key2 = PrivateKey::try_new([2; 32]).unwrap();
    let addr1 = AccountId::from(&PublicKey::new_from_private_key(&key1));
    let addr2 = AccountId::from(&PublicKey::new_from_private_key(&key2));
    let expected_public_state = {
        let mut this = HashMap::new();
        this.insert(
            addr1,
            Account {
                balance: 100,
                ..Account::default()
            },
        );
        this.insert(
            addr2,
            Account {
                balance: 151,
                ..Account::default()
            },
        );
        this
    };
    let expected_builtin_programs = HashMap::new();

    let state =
        V03State::new().with_public_account_balances([(addr1, 100_u128), (addr2, 151_u128)]);

    assert_eq!(state.public_state, expected_public_state);
    assert_eq!(state.programs, expected_builtin_programs);
}

#[test]
fn new_includes_nullifiers_for_private_accounts() {
    let keys1 = test_private_account_keys_1();
    let keys2 = test_private_account_keys_2();

    let account = Account {
        balance: 100,
        ..Account::default()
    };

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
    assert!(!state.programs.contains_key(&program_id));

    state.insert_program(program_to_insert);

    assert!(state.programs.contains_key(&program_id));
}

#[test]
fn insert_program_makes_program_commitment_provable() {
    let mut state = V03State::new();
    let program_to_insert = crate::test_methods::simple_balance_transfer();
    let commitment = ProgramCommitment::new(program_to_insert.id());
    assert!(
        state
            .get_proof_for_program_commitment(&commitment)
            .is_none()
    );

    state.insert_program(program_to_insert);

    assert!(
        state
            .get_proof_for_program_commitment(&commitment)
            .is_some(),
        "the inserted program's commitment should be provable"
    );
}

#[test]
fn program_deployment_transaction_makes_program_commitment_provable() {
    let mut state = V03State::new();
    let bytecode = crate::test_methods::simple_balance_transfer()
        .elf()
        .to_vec();
    let message = crate::program_deployment_transaction::Message::new(bytecode);
    let tx = crate::program_deployment_transaction::ProgramDeploymentTransaction::new(message);

    state
        .transition_from_program_deployment_transaction(&tx)
        .expect("a fresh program deployment should succeed");

    let program_id = crate::test_methods::simple_balance_transfer().id();
    let commitment = ProgramCommitment::new(program_id);
    assert!(
        state
            .get_proof_for_program_commitment(&commitment)
            .is_some(),
        "the deployed program's commitment should be provable"
    );
}

#[test]
fn program_deployment_transaction_upgrade_is_not_yet_supported() {
    let mut state = V03State::new();
    let message = crate::program_deployment_transaction::Message::Upgrade(
        crate::program_deployment_transaction::UpgradeMessage {
            program_id: crate::test_methods::simple_balance_transfer().id(),
            auth_withdraw: false,
            elf: crate::test_methods::simple_balance_transfer()
                .elf()
                .to_vec(),
        },
    );
    let tx = crate::program_deployment_transaction::ProgramDeploymentTransaction::new(message);

    let result = state.transition_from_program_deployment_transaction(&tx);

    assert!(matches!(
        result,
        Err(LeeError::ProgramUpgradeNotYetSupported)
    ));
}

#[test]
fn get_account_by_account_id_non_default_account() {
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
fn builtin_programs_getter() {
    let state = V03State::new();

    let builtin_programs = state.programs();

    assert_eq!(builtin_programs, &state.programs);
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

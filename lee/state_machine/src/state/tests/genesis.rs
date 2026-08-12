use fee_core::{
    FeeState, distribute,
    params::{BASE_FEE_EXEC_MIN, BASE_FEE_STOR_MIN, SMOOTHING_WINDOW},
};

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
fn genesis_fee_state_matches_spec() {
    let state = V03State::new();

    let fee_state = state.fee_state();
    assert_eq!(fee_state.base_fee_exec, BASE_FEE_EXEC_MIN);
    assert_eq!(fee_state.base_fee_stor, BASE_FEE_STOR_MIN);
    assert_eq!(fee_state.escrow, 0);
    assert_eq!(fee_state.window, [0_u128; SMOOTHING_WINDOW]);
    assert_eq!(fee_state.cursor, 0);
    assert_eq!(fee_state.payout_carry, 0);
}

#[test]
fn seeding_helpers_leave_the_fee_state_at_genesis() {
    let state = V03State::new()
        .with_public_account_balances([(AccountId::new([1; 32]), 100_u128)])
        .with_test_programs();

    assert_eq!(state.fee_state(), &FeeState::genesis().unwrap());
}

/// A fee state whose ring buffer is mid-rotation: `blocks` distributions of
/// distinct revenues leave `cursor` off zero and every slot holding a
/// different value.
fn mid_rotation_fee_state(blocks: u128) -> FeeState {
    let mut fee_state = FeeState::genesis().unwrap();
    for i in 0..blocks {
        distribute(&mut fee_state, 1_000 + i * 1_000).unwrap();
    }
    fee_state
}

/// Drives `fee_state` through a fixed revenue sequence, collecting the payouts.
fn payout_sequence(fee_state: &mut FeeState, blocks: usize) -> Vec<u128> {
    (0..blocks)
        .map(|i| {
            let revenue = 500 + u128::try_from(i).unwrap() * 13;
            distribute(fee_state, revenue).unwrap()
        })
        .collect()
}

#[test]
fn state_roundtrip_preserves_a_mid_rotation_fee_state() {
    let mut state = V03State::new();
    *state.fee_state_mut() = mid_rotation_fee_state(73);
    assert_ne!(state.fee_state().cursor, 0, "window must be mid-rotation");

    let bytes = borsh::to_vec(&state).unwrap();
    let decoded: V03State = borsh::from_slice(&bytes).unwrap();
    assert_eq!(state, decoded);

    // The encoding pins the ring buffer *as rotated*, so what has to survive is
    // payout behaviour, not just the bytes.
    let mut original = state.fee_state().clone();
    let mut restored = decoded.fee_state().clone();
    assert_eq!(
        payout_sequence(&mut original, SMOOTHING_WINDOW * 2),
        payout_sequence(&mut restored, SMOOTHING_WINDOW * 2)
    );
    assert_eq!(original, restored);
}

#[test]
fn cursor_position_is_semantic() {
    // Same slot values, cursor shifted by one: the eviction order differs, so
    // the payout sequences diverge. This is what gives the roundtrip test above
    // its teeth, and why `FeeState` bytes are not a canonical form.
    let mut original = mid_rotation_fee_state(73);
    let mut rotated = original.clone();
    let shifted = original.cursor + 1;
    assert!(usize::from(shifted) < SMOOTHING_WINDOW);
    rotated.cursor = shifted;

    assert_ne!(
        payout_sequence(&mut original, SMOOTHING_WINDOW),
        payout_sequence(&mut rotated, SMOOTHING_WINDOW)
    );
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

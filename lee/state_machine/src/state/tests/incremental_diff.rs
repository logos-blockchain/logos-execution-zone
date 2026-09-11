use super::*;

// Host-side mirror of `stripped_token`'s `Instruction`/`TokenAccountData` — the guest crate
// isn't a host dependency, so these can't be imported directly, only match the borsh layout.
#[derive(borsh::BorshSerialize)]
enum StrippedTokenInstruction {
    Initialize { balance: u128 },
    Transfer { amount: u128 },
}

#[derive(borsh::BorshDeserialize)]
struct TokenAccountData {
    balance: u128,
}

fn token_balance(state: &V03State, account_id: AccountId) -> u128 {
    let data: TokenAccountData = borsh::from_slice(
        state.get_account_by_id(account_id).data.as_ref(),
    )
    .expect("account data must decode as TokenAccountData: did Incremental resolution run?");
    data.balance
}

fn initialize_token_account(
    state: &mut V03State,
    stripped_token_program_id: AccountId,
    account_id: AccountId,
    balance: u128,
    block_id: BlockId,
) {
    let message = public_transaction::Message::try_new(
        stripped_token_program_id,
        vec![account_id],
        vec![],
        StrippedTokenInstruction::Initialize { balance },
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    state
        .transition_from_public_transaction(
            &PublicTransaction::new(message, witness_set),
            block_id,
            0,
        )
        .unwrap();
}

/// End-to-end proof that `resolve_diff` actually invokes `Incremental` and resolves
/// `stripped_token`'s `TokenDiff` deltas into real balances: if it silently fell back to
/// copy/replace instead, the account's `data` would hold raw `TokenDiff` bytes, and decoding it
/// here as `TokenAccountData` would fail outright.
#[test]
fn stripped_token_transfer_resolves_through_incremental_dispatch() {
    let mut state = V03State::new().with_test_programs();
    let program_id: AccountId = crate::test_methods::stripped_token().id().into();
    let sender_id = AccountId::new([1; 32]);
    let receiver_id = AccountId::new([2; 32]);

    // Initialize only the sender — the receiver stays untouched, exercising `Incremental`'s
    // empty-data-defaults-to-zero path for a never-initialized account.
    let initialize_message = public_transaction::Message::try_new(
        program_id,
        vec![sender_id],
        vec![],
        StrippedTokenInstruction::Initialize { balance: 100 },
    )
    .unwrap();
    let initialize_witness_set =
        public_transaction::WitnessSet::for_message(&initialize_message, &[]);
    state
        .transition_from_public_transaction(
            &PublicTransaction::new(initialize_message, initialize_witness_set),
            1,
            0,
        )
        .unwrap();

    assert_eq!(token_balance(&state, sender_id), 100);
    // Account.balance (native) is a completely separate field this program never touches.
    assert_eq!(state.get_account_by_id(sender_id).balance, 0);

    let transfer_message = public_transaction::Message::try_new(
        program_id,
        vec![sender_id, receiver_id],
        vec![],
        StrippedTokenInstruction::Transfer { amount: 30 },
    )
    .unwrap();
    let transfer_witness_set = public_transaction::WitnessSet::for_message(&transfer_message, &[]);
    state
        .transition_from_public_transaction(
            &PublicTransaction::new(transfer_message, transfer_witness_set),
            2,
            0,
        )
        .unwrap();

    assert_eq!(token_balance(&state, sender_id), 70);
    assert_eq!(token_balance(&state, receiver_id), 30);
    assert_eq!(state.get_account_by_id(sender_id).balance, 0);
    assert_eq!(state.get_account_by_id(receiver_id).balance, 0);
}

fn robinhood_message(
    robinhood_program_id: AccountId,
    stripped_token_program_id: ProgramId,
    account1_id: AccountId,
    account2_id: AccountId,
) -> public_transaction::Message {
    public_transaction::Message::try_new(
        robinhood_program_id,
        vec![account1_id, account2_id],
        vec![],
        stripped_token_program_id,
    )
    .unwrap()
}

/// `stripped_token_robinhood` reads both accounts' real balances to pick a route, but its own
/// diffs are always unchanged — the actual movement happens in the chained `stripped_token`
/// call. This is the scenario `ExecutionMode` mode-locking exists for: robinhood's read is
/// inherently `Bound` (it needs live values now), while the chained `Transfer` on the same
/// accounts would otherwise be free to defer.
#[test]
fn stripped_token_robinhood_moves_one_unit_from_the_larger_account_to_the_smaller() {
    let mut state = V03State::new().with_test_programs();
    let stripped_token_program = crate::test_methods::stripped_token();
    let stripped_token_program_id: AccountId = stripped_token_program.id().into();
    let robinhood_program_id: AccountId =
        crate::test_methods::stripped_token_robinhood().id().into();
    let account1_id = AccountId::new([1; 32]);
    let account2_id = AccountId::new([2; 32]);

    initialize_token_account(&mut state, stripped_token_program_id, account1_id, 100, 1);
    initialize_token_account(&mut state, stripped_token_program_id, account2_id, 40, 2);

    let message = robinhood_message(
        robinhood_program_id,
        stripped_token_program.id(),
        account1_id,
        account2_id,
    );
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    state
        .transition_from_public_transaction(&PublicTransaction::new(message, witness_set), 3, 0)
        .unwrap();

    assert_eq!(token_balance(&state, account1_id), 99);
    assert_eq!(token_balance(&state, account2_id), 41);
}

/// Same as above with sizes swapped, proving the route follows whichever account is larger, not
/// a fixed position.
#[test]
fn stripped_token_robinhood_follows_whichever_account_is_actually_larger() {
    let mut state = V03State::new().with_test_programs();
    let stripped_token_program = crate::test_methods::stripped_token();
    let stripped_token_program_id: AccountId = stripped_token_program.id().into();
    let robinhood_program_id: AccountId =
        crate::test_methods::stripped_token_robinhood().id().into();
    let account1_id = AccountId::new([1; 32]);
    let account2_id = AccountId::new([2; 32]);

    // account2 is now the larger one — the opposite of the previous test.
    initialize_token_account(&mut state, stripped_token_program_id, account1_id, 40, 1);
    initialize_token_account(&mut state, stripped_token_program_id, account2_id, 100, 2);

    let message = robinhood_message(
        robinhood_program_id,
        stripped_token_program.id(),
        account1_id,
        account2_id,
    );
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    state
        .transition_from_public_transaction(&PublicTransaction::new(message, witness_set), 3, 0)
        .unwrap();

    assert_eq!(token_balance(&state, account1_id), 41);
    assert_eq!(token_balance(&state, account2_id), 99);
}

/// Equal balances trigger no chained call at all — a real no-op, not a same-amount round trip.
#[test]
fn stripped_token_robinhood_does_nothing_when_balances_are_equal() {
    let mut state = V03State::new().with_test_programs();
    let stripped_token_program = crate::test_methods::stripped_token();
    let stripped_token_program_id: AccountId = stripped_token_program.id().into();
    let robinhood_program_id: AccountId =
        crate::test_methods::stripped_token_robinhood().id().into();
    let account1_id = AccountId::new([1; 32]);
    let account2_id = AccountId::new([2; 32]);

    initialize_token_account(&mut state, stripped_token_program_id, account1_id, 50, 1);
    initialize_token_account(&mut state, stripped_token_program_id, account2_id, 50, 2);

    let message = robinhood_message(
        robinhood_program_id,
        stripped_token_program.id(),
        account1_id,
        account2_id,
    );
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    state
        .transition_from_public_transaction(&PublicTransaction::new(message, witness_set), 3, 0)
        .unwrap();

    assert_eq!(token_balance(&state, account1_id), 50);
    assert_eq!(token_balance(&state, account2_id), 50);
}

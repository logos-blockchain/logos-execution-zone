use super::*;

/// A program can drop an entire account from its own output by simply omitting its
/// `AccountStateDiff` — `validate_execution` has no way to catch this on its own, since a
/// shorter `state_diffs` list is perfectly well-formed. This must still be rejected: every
/// account the caller declared in the transaction must appear somewhere in the final diff.
#[test]
fn program_should_fail_if_it_drops_a_declared_account() {
    // Both accounts need a non-default program_owner: an account left at DEFAULT_PROGRAM_ID with
    // non-default data would itself violate the (separate, pre-existing) "claim before mutating a
    // default-owned account" rule the moment it's echoed back — unrelated to what this test
    // targets. `with_public_account_balances` leaves program_owner at DEFAULT_PROGRAM_ID, so use
    // `with_public_accounts` to set it explicitly instead.
    let mut state = V03State::new()
        .with_public_accounts([
            (
                AccountId::new([1; 32]),
                Account {
                    program_owner: crate::test_methods::dropped_account().deployed_account_id(),
                    balance: 100,
                    ..Account::default()
                },
            ),
            (
                AccountId::new([2; 32]),
                Account {
                    program_owner: crate::test_methods::dropped_account().deployed_account_id(),
                    balance: 0,
                    ..Account::default()
                },
            ),
        ])
        .with_test_programs();
    let account_ids = vec![AccountId::new([1; 32]), AccountId::new([2; 32])];
    let program_id = crate::test_methods::dropped_account().deployed_account_id();
    let message =
        public_transaction::Message::try_new(program_id, account_ids, vec![], ()).unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::DeclaredAccountMissingFromOutput { account_id }
            )) if account_id == AccountId::new([2; 32])
        ),
        "expected DeclaredAccountMissingFromOutput for the dropped account, got {result:?}"
    );
}

#[test]
fn program_should_fail_if_transfers_balance_from_non_owned_account() {
    let sender_account_id = AccountId::new([1; 32]);
    let receiver_account_id = AccountId::new([2; 32]);
    let mut state = V03State::new()
        .with_public_account_balances([(sender_account_id, 100)])
        .with_test_programs();
    let balance_to_move: u128 = 1;
    let program_id = crate::test_methods::simple_balance_transfer().deployed_account_id();
    assert_ne!(
        state.get_account_by_id(sender_account_id).program_owner,
        program_id
    );
    let message = public_transaction::Message::try_new(
        program_id,
        vec![sender_account_id, receiver_account_id],
        vec![],
        balance_to_move,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::UnauthorizedBalanceDecrease { account_id: err_account_id, owner_account_id, executing_account_id }
        ))) if err_account_id == sender_account_id && owner_account_id != program_id && executing_account_id == program_id
    ));
}

#[test]
fn program_should_fail_if_modifies_data_of_non_owned_account() {
    let initial_data = HashMap::new();
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs()
        .with_non_default_accounts_but_default_program_owners();
    let account_id = AccountId::new([255; 32]);
    let program_id = crate::test_methods::data_changer().deployed_account_id();

    assert_ne!(state.get_account_by_id(account_id), Account::default());
    assert_ne!(
        state.get_account_by_id(account_id).program_owner,
        program_id
    );
    let message =
        public_transaction::Message::try_new(program_id, vec![account_id], vec![], vec![0_u8])
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::UnauthorizedDataModification { account_id: err_account_id, executing_account_id }
        ))) if err_account_id == account_id && executing_account_id == program_id
    ));
}

#[test]
fn program_should_fail_if_does_not_preserve_total_balance_by_minting() {
    let initial_data = HashMap::new();
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs();
    let account_id = AccountId::new([1; 32]);
    let program_id = crate::test_methods::minter().deployed_account_id();

    let message =
        public_transaction::Message::try_new(program_id, vec![account_id], vec![], ()).unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 2, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::MismatchedTotalBalance { total_added, total_subbed }
        ))) if total_added == 1.into() && total_subbed == 0.into()
    ));
}

#[test]
fn program_should_fail_if_does_not_preserve_total_balance_by_burning() {
    let initial_data = HashMap::new();
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs()
        .with_account_owned_by_burner_program();
    let program_id = crate::test_methods::burner().deployed_account_id();
    let account_id = AccountId::new([252; 32]);
    assert_eq!(
        state.get_account_by_id(account_id).program_owner,
        program_id
    );
    let balance_to_burn: u128 = 1;
    assert!(state.get_account_by_id(account_id).balance > balance_to_burn);

    let message =
        public_transaction::Message::try_new(program_id, vec![account_id], vec![], balance_to_burn)
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);
    let result = state.transition_from_public_transaction(&tx, 2, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::MismatchedTotalBalance { total_added, total_subbed }
        ))) if total_added == 0.into() && total_subbed == 1.into()
    ));
}

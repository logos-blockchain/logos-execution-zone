use super::*;

#[test]
fn program_should_fail_if_output_accounts_exceed_inputs() {
    let mut state = V03State::new()
        .with_public_account_balances(native(), [(AccountId::new([1; 32]), 0)])
        .with_test_programs();
    let account_ids = vec![AccountId::new([1; 32])];
    let program_id = crate::test_methods::extra_output().id();
    let message = public_transaction::Message::try_new(
        program_id,
        slots_of(program_id, &account_ids),
        vec![],
        (),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::ExecutionValidationFailed(
                ExecutionValidationError::MismatchedPreStatePostStateLength {
                    pre_state_length,
                    post_state_length
                }
            )
        )) if pre_state_length == 1 && post_state_length == 2
    ));
}

#[test]
fn program_should_fail_with_missing_output_accounts() {
    let mut state = V03State::new()
        .with_public_account_balances(native(), [(AccountId::new([1; 32]), 100)])
        .with_test_programs();
    let account_ids = vec![AccountId::new([1; 32]), AccountId::new([2; 32])];
    let program_id = crate::test_methods::missing_output().id();
    let message = public_transaction::Message::try_new(
        program_id,
        slots_of(program_id, &account_ids),
        vec![],
        (),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::ExecutionValidationFailed(
                ExecutionValidationError::MismatchedPreStatePostStateLength {
                    pre_state_length,
                    post_state_length
                }
            )
        )) if pre_state_length == 2 && post_state_length == 1
    ));
}

/// A program can drop an entire account from its own output — both its `pre_state` and
/// `post_state` together, not just one side — while staying internally consistent
/// (`pre_states.len() == post_states.len()` within its own report, so `validate_execution`'s
/// length check alone can't catch it). This must still be rejected: every account the caller
/// declared in the transaction must appear somewhere in the final diff.
#[test]
fn program_should_fail_if_it_drops_a_declared_account() {
    let mut state = V03State::new()
        .with_public_account_balances(
            native(),
            [(AccountId::new([1; 32]), 100), (AccountId::new([2; 32]), 0)],
        )
        .with_test_programs();
    let account_ids = vec![AccountId::new([1; 32]), AccountId::new([2; 32])];
    let program_id = crate::test_methods::dropped_account().id();
    let message = public_transaction::Message::try_new(
        program_id,
        slots_of(program_id, &account_ids),
        vec![],
        (),
    )
    .unwrap();
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
fn program_should_fail_if_transfers_balance_from_a_foreign_slot() {
    let sender_account_id = AccountId::new([1; 32]);
    let receiver_account_id = AccountId::new([2; 32]);
    let foreign_program_id = crate::test_methods::noop().id();
    let mut state = V03State::new()
        .with_public_account_balances(foreign_program_id, [(sender_account_id, 100)])
        .with_test_programs();
    let balance_to_move: u128 = 1;
    let program_id = native();
    // The sender's 100 sits in another program's slot, so the executing program sees nothing.
    assert_eq!(
        state
            .get_account_by_id(sender_account_id)
            .balance(program_id),
        0
    );
    let message = public_transaction::Message::try_new(
        program_id,
        slots_of(program_id, &[sender_account_id, receiver_account_id]),
        vec![],
        balance_to_move,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(result, Err(LeeError::ProgramExecutionFailed(_))));
    assert_eq!(
        state
            .get_account_by_id(sender_account_id)
            .balance(foreign_program_id),
        100
    );
    assert_eq!(
        state.get_account_by_id(receiver_account_id),
        Account::default()
    );
}

#[test]
fn program_may_write_its_own_slot_without_touching_foreign_slots() {
    let initial_data = HashMap::new();
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs()
        .with_accounts_untouched_by_the_executing_program();
    let account_id = AccountId::new([255; 32]);
    let program_id = crate::test_methods::data_changer().id();
    let foreign_program_id = crate::test_methods::noop().id();

    assert_ne!(state.get_account_by_id(account_id), Account::default());
    assert!(
        state
            .get_account_by_id(account_id)
            .slot(program_id)
            .is_none()
    );
    let message = public_transaction::Message::try_new(
        program_id,
        slots_of(program_id, &[account_id]),
        vec![],
        vec![0_u8],
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(
        result.is_ok(),
        "writing one's own slot is allowed: {result:?}"
    );
    let account = state.get_account_by_id(account_id);
    assert_eq!(account.data(program_id).as_ref(), [0_u8].as_slice());
    assert_eq!(account.balance(foreign_program_id), 100);
    assert!(account.data(foreign_program_id).is_empty());
}

#[test]
fn program_should_fail_if_does_not_preserve_total_balance_by_minting() {
    let initial_data = HashMap::new();
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs();
    let account_id = AccountId::new([1; 32]);
    let program_id = crate::test_methods::minter().id();

    let message = public_transaction::Message::try_new(
        program_id,
        slots_of(program_id, &[account_id]),
        vec![],
        (),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 2, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::MismatchedTotalBalance { total_balance_pre_states, total_balance_post_states }
        ))) if total_balance_pre_states == 0.into() && total_balance_post_states == 1.into()
    ));
}

#[test]
fn program_should_fail_if_does_not_preserve_total_balance_by_burning() {
    let initial_data = HashMap::new();
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs()
        .with_account_owned_by_burner_program();
    let program_id = crate::test_methods::burner().id();
    let account_id = AccountId::new([252; 32]);
    let balance_to_burn: u128 = 1;
    assert!(state.get_account_by_id(account_id).balance(program_id) > balance_to_burn);

    let message = public_transaction::Message::try_new(
        program_id,
        slots_of(program_id, &[account_id]),
        vec![],
        balance_to_burn,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);
    let result = state.transition_from_public_transaction(&tx, 2, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::MismatchedTotalBalance { total_balance_pre_states, total_balance_post_states }
        ))) if total_balance_pre_states == 100.into() && total_balance_post_states == 99.into()
    ));
}

/// Rule 4, data half: a program may not rewrite a slot that is not its own. Nothing else
/// rejects this — the account balances are untouched, so conservation is satisfied.
#[test]
fn program_should_fail_if_writes_data_of_a_foreign_slot() {
    let mut state = V03State::new()
        .with_public_accounts(HashMap::new())
        .with_test_programs()
        .with_accounts_untouched_by_the_executing_program();
    let account_id = AccountId::new([255; 32]);
    let program_id = crate::test_methods::foreign_slot_writer().id();
    let foreign_program_id = crate::test_methods::noop().id();

    // The position names the foreign namespace: that is what makes the slot the writer
    // reaches for one it does not own.
    let message = public_transaction::Message::try_new(
        program_id,
        slots_of(foreign_program_id, &[account_id]),
        vec![],
        (),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::ExecutionValidationFailed(
                    ExecutionValidationError::ForeignSlotModified { .. }
                )
            ))
        ),
        "expected ForeignSlotModified, got: {result:?}"
    );
    assert!(
        state
            .get_account_by_id(account_id)
            .data(foreign_program_id)
            .is_empty()
    );
}

/// Rule 4, debit half: moving a foreign slot's balance into one's own conserves the total,
/// so rule 6 passes and only rule 4 stands between a program and its neighbour's funds.
#[test]
fn program_should_fail_if_drains_a_foreign_slot() {
    let mut state = V03State::new()
        .with_public_accounts(HashMap::new())
        .with_test_programs()
        .with_accounts_untouched_by_the_executing_program();
    let account_id = AccountId::new([255; 32]);
    let program_id = crate::test_methods::foreign_slot_drainer().id();
    let foreign_program_id = crate::test_methods::noop().id();

    // `[the foreign slot it drains, its own slot it drains into]`, both at one account.
    let message = public_transaction::Message::try_new(
        program_id,
        vec![
            SlotRef::new(account_id, foreign_program_id),
            SlotRef::new(account_id, program_id),
        ],
        vec![],
        (),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::ExecutionValidationFailed(
                    ExecutionValidationError::ForeignSlotModified { .. }
                )
            ))
        ),
        "expected ForeignSlotModified, got: {result:?}"
    );
    assert_eq!(
        state
            .get_account_by_id(account_id)
            .balance(foreign_program_id),
        100
    );
}

use lee_core::program::InstructionData;

use super::*;

#[test]
fn program_should_fail_if_modifies_nonces() {
    let account_id = AccountId::new([1; 32]);
    let mut state = V03State::new()
        .with_public_account_balances([(account_id, 100)])
        .with_test_programs();
    let account_ids = vec![account_id];
    let program_id = crate::test_methods::nonce_changer().id();
    let message =
        public_transaction::Message::try_new(program_id.into(), account_ids, vec![], ()).unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::ExecutionValidationFailed(
                ExecutionValidationError::ModifiedNonce { account_id: err_account_id }
            )
        )) if err_account_id == account_id
    ));
}

#[test]
fn program_should_fail_if_output_accounts_exceed_inputs() {
    let mut state = V03State::new()
        .with_public_account_balances([(AccountId::new([1; 32]), 0)])
        .with_test_programs();
    let account_ids = vec![AccountId::new([1; 32])];
    let program_id = crate::test_methods::extra_output().id();
    let message =
        public_transaction::Message::try_new(program_id.into(), account_ids, vec![], ()).unwrap();
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
        .with_public_account_balances([(AccountId::new([1; 32]), 100)])
        .with_test_programs();
    let account_ids = vec![AccountId::new([1; 32]), AccountId::new([2; 32])];
    let program_id = crate::test_methods::missing_output().id();
    let message =
        public_transaction::Message::try_new(program_id.into(), account_ids, vec![], ()).unwrap();
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
                    program_owner: crate::test_methods::dropped_account().id().into(),
                    balance: 100,
                    ..Account::default()
                },
            ),
            (
                AccountId::new([2; 32]),
                Account {
                    program_owner: crate::test_methods::dropped_account().id().into(),
                    balance: 0,
                    ..Account::default()
                },
            ),
        ])
        .with_test_programs();
    let account_ids = vec![AccountId::new([1; 32]), AccountId::new([2; 32])];
    let program_id = crate::test_methods::dropped_account().id();
    let message =
        public_transaction::Message::try_new(program_id.into(), account_ids, vec![], ()).unwrap();
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
fn program_should_fail_if_modifies_program_owner_with_only_non_default_program_owner() {
    let initial_data = [(
        AccountId::new([1; 32]),
        Account {
            program_owner: crate::test_methods::simple_balance_transfer().id().into(),
            ..Account::default()
        },
    )];
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs();
    let account_id = AccountId::new([1; 32]);
    let account = state.get_account_by_id(account_id);
    // Assert the target account only differs from the default account in the program owner
    // field
    assert_ne!(account.program_owner, Account::default().program_owner);
    assert_eq!(account.balance, Account::default().balance);
    assert_eq!(account.nonce, Account::default().nonce);
    assert_eq!(account.data, Account::default().data);
    let program_id = crate::test_methods::program_owner_changer().id();
    let message =
        public_transaction::Message::try_new(program_id.into(), vec![account_id], vec![], ())
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::ModifiedProgramOwner { account_id: err_account_id }
        ))) if err_account_id == account_id
    ));
}

#[test]
fn program_should_fail_if_modifies_program_owner_with_only_non_default_balance() {
    let initial_data = HashMap::new();
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs()
        .with_non_default_accounts_but_default_program_owners();
    let account_id = AccountId::new([255; 32]);
    let account = state.get_account_by_id(account_id);
    // Assert the target account only differs from the default account in balance field
    assert_eq!(account.program_owner, Account::default().program_owner);
    assert_ne!(account.balance, Account::default().balance);
    assert_eq!(account.nonce, Account::default().nonce);
    assert_eq!(account.data, Account::default().data);
    let program_id = crate::test_methods::program_owner_changer().id();
    let message =
        public_transaction::Message::try_new(program_id.into(), vec![account_id], vec![], ())
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::ModifiedProgramOwner { account_id: err_account_id }
        ))) if err_account_id == account_id
    ));
}

#[test]
fn program_should_fail_if_modifies_program_owner_with_only_non_default_nonce() {
    let initial_data = HashMap::new();
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs()
        .with_non_default_accounts_but_default_program_owners();
    let account_id = AccountId::new([254; 32]);
    let account = state.get_account_by_id(account_id);
    // Assert the target account only differs from the default account in nonce field
    assert_eq!(account.program_owner, Account::default().program_owner);
    assert_eq!(account.balance, Account::default().balance);
    assert_ne!(account.nonce, Account::default().nonce);
    assert_eq!(account.data, Account::default().data);
    let program_id = crate::test_methods::program_owner_changer().id();
    let message =
        public_transaction::Message::try_new(program_id.into(), vec![account_id], vec![], ())
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::ModifiedProgramOwner { account_id: err_account_id }
        ))) if err_account_id == account_id
    ));
}

#[test]
fn program_should_fail_if_modifies_program_owner_with_only_non_default_data() {
    let initial_data = HashMap::new();
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs()
        .with_non_default_accounts_but_default_program_owners();
    let account_id = AccountId::new([253; 32]);
    let account = state.get_account_by_id(account_id);
    // Assert the target account only differs from the default account in data field
    assert_eq!(account.program_owner, Account::default().program_owner);
    assert_eq!(account.balance, Account::default().balance);
    assert_eq!(account.nonce, Account::default().nonce);
    assert_ne!(account.data, Account::default().data);
    let program_id = crate::test_methods::program_owner_changer().id();
    let message =
        public_transaction::Message::try_new(program_id.into(), vec![account_id], vec![], ())
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::ModifiedProgramOwner { account_id: err_account_id }
        ))) if err_account_id == account_id
    ));
}

#[test]
fn program_should_fail_if_transfers_balance_from_non_owned_account() {
    let sender_account_id = AccountId::new([1; 32]);
    let receiver_account_id = AccountId::new([2; 32]);
    let mut state = V03State::new()
        .with_public_account_balances([(sender_account_id, 100)])
        .with_test_programs();
    let balance_to_move: u128 = 1;
    let program_id = crate::test_methods::simple_balance_transfer().id();
    assert_ne!(
        state.get_account_by_id(sender_account_id).program_owner,
        program_id.into()
    );
    let message = public_transaction::Message::try_new(
        program_id.into(),
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
        ))) if err_account_id == sender_account_id && owner_account_id != program_id.into() && executing_account_id == program_id.into()
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
    let program_id = crate::test_methods::data_changer().id();

    assert_ne!(state.get_account_by_id(account_id), Account::default());
    assert_ne!(
        state.get_account_by_id(account_id).program_owner,
        program_id.into()
    );
    let message =
        public_transaction::Message::try_new(program_id.into(), vec![account_id], vec![], vec![0_u8])
            .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::UnauthorizedDataModification { account_id: err_account_id, executing_account_id }
        ))) if err_account_id == account_id && executing_account_id == program_id.into()
    ));
}

#[test]
fn program_should_fail_if_does_not_preserve_total_balance_by_minting() {
    let initial_data = HashMap::new();
    let mut state = V03State::new()
        .with_public_accounts(initial_data)
        .with_test_programs();
    let account_id = AccountId::new([1; 32]);
    let program_id = crate::test_methods::minter().id();

    let message =
        public_transaction::Message::try_new(program_id.into(), vec![account_id], vec![], ())
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

/// A chained call may only name an account the transaction declared or an earlier call already
/// touched — never an arbitrary id that merely exists (or not) in global state.
#[test]
fn program_should_fail_if_it_references_an_undeclared_account() {
    let account_id = AccountId::new([1; 32]);
    let undeclared_account_id = AccountId::new([99; 32]);
    let mut state = V03State::new()
        .with_public_account_balances([(account_id, 0)])
        .with_test_programs();
    let program_id = crate::test_methods::references_undeclared_account().id();
    let callee_id = crate::test_methods::noop().id();
    let instruction: (ProgramId, InstructionData, AccountId) = (
        callee_id,
        Program::serialize_instruction(()).unwrap(),
        undeclared_account_id,
    );
    let message = public_transaction::Message::try_new(
        program_id.into(),
        vec![account_id],
        vec![],
        instruction,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::UnknownChainedCallAccount { account_id: err_account_id }
            )) if err_account_id == undeclared_account_id
        ),
        "expected UnknownChainedCallAccount for the undeclared account, got {result:?}"
    );
}

/// A program can echo its real `pre_states` honestly and still fabricate an extra, untouched
/// account in its own output — one it was never given via `ChainedCall.pre_state_ids`. This must be
/// rejected independently of whether the fabricated account happens to already exist anywhere.
#[test]
fn program_should_fail_if_it_injects_an_undeclared_pre_state() {
    let account_id = AccountId::new([1; 32]);
    let fabricated_account_id = AccountId::new([123; 32]);
    let mut state = V03State::new()
        .with_public_account_balances([(account_id, 0)])
        .with_test_programs();
    let program_id = crate::test_methods::injects_undeclared_pre_state().id();
    let message = public_transaction::Message::try_new(
        program_id.into(),
        vec![account_id],
        vec![],
        fabricated_account_id,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::UndeclaredAccountInProgramOutput {
                    account_id: err_account_id,
                    ..
                }
            )) if err_account_id == fabricated_account_id
        ),
        "expected UndeclaredAccountInProgramOutput for the fabricated account, got {result:?}"
    );
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
    assert_eq!(
        state.get_account_by_id(account_id).program_owner,
        program_id.into()
    );
    let balance_to_burn: u128 = 1;
    assert!(state.get_account_by_id(account_id).balance > balance_to_burn);

    let message = public_transaction::Message::try_new(
        program_id.into(),
        vec![account_id],
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

/// A callee must account for exactly the accounts its caller named. `dropped_account` is handed
/// two and journals one, so the chained call is rejected — without this, a program's journal need
/// not correspond to the accounts it was actually called with.
#[test]
fn program_should_fail_if_a_callee_drops_an_account_its_caller_named() {
    let owner = crate::test_methods::dropped_account().id();
    let held = |balance| Account {
        program_owner: owner.into(),
        balance,
        ..Account::default()
    };
    let mut state = V03State::new()
        .with_public_accounts([
            (AccountId::new([1; 32]), held(100)),
            (AccountId::new([2; 32]), held(0)),
        ])
        .with_test_programs();

    // The forwarder names both accounts for the callee; the callee journals only the first.
    let message = public_transaction::Message::try_new(
        crate::test_methods::non_delegating_forwarder().id().into(),
        vec![AccountId::new([1; 32]), AccountId::new([2; 32])],
        vec![],
        (owner, Vec::<u8>::new(), true, Vec::<PdaSeed>::new()),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::ChainedCallAccountsMismatch { program_id }
            )) if program_id == owner
        ),
        "expected ChainedCallAccountsMismatch for the callee, got {result:?}"
    );
}

use lee_core::program::InstructionData;

use super::*;

/// A program can drop an entire account from its own output by simply omitting its
/// `AccountStateDiff` — `validate_execution` has no way to catch this on its own, since a
/// shorter `state_diffs` list is perfectly well-formed. This must still be rejected: every
/// account the caller declared in the transaction must appear somewhere in the final diff.
#[test]
fn program_should_fail_if_it_drops_a_declared_account() {
    let mut state = V03State::new()
        .with_public_account_balances([
            (AccountId::new([1; 32]), 100),
            (AccountId::new([2; 32]), 0),
        ])
        .with_test_programs();
    let shard_selectors = vec![
        ProgramShardSelector::balance_only(AccountId::new([1; 32])),
        ProgramShardSelector::balance_only(AccountId::new([2; 32])),
    ];
    let program_id: AccountId = crate::test_methods::dropped_account().id().into();
    let message =
        public_transaction::Message::try_new(program_id, shard_selectors, vec![], ()).unwrap();
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
fn program_should_fail_if_it_debits_an_unauthorized_account() {
    let sender_account_id = AccountId::new([1; 32]);
    let receiver_account_id = AccountId::new([2; 32]);
    let mut state = V03State::new()
        .with_public_account_balances([(sender_account_id, 100)])
        .with_test_programs();
    let balance_to_move: u128 = 1;
    let program_id: AccountId = crate::test_methods::simple_balance_transfer().id().into();
    let message = public_transaction::Message::try_new(
        program_id,
        vec![
            ProgramShardSelector::balance_only(sender_account_id),
            ProgramShardSelector::balance_only(receiver_account_id),
        ],
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
            ExecutionValidationError::UnauthorizedBalanceDecrease { account_id: err_account_id }
        ))) if err_account_id == sender_account_id
    ));
}

#[test]
fn program_should_transfer_balance_from_an_authorized_account() {
    let sender_key = PrivateKey::try_new([3; 32]).unwrap();
    let sender_account_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
    let receiver_account_id = AccountId::new([2; 32]);
    let program_id: AccountId = crate::test_methods::simple_balance_transfer().id().into();
    let mut state = V03State::new()
        .with_public_account_balances([(sender_account_id, 100), (receiver_account_id, 0)])
        .with_test_programs();
    let message = public_transaction::Message::try_new(
        program_id,
        vec![
            ProgramShardSelector::balance_only(sender_account_id),
            ProgramShardSelector::balance_only(receiver_account_id),
        ],
        vec![Nonce(0)],
        1_u128,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&sender_key]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(state.get_account_by_id(sender_account_id).data.balance, 99);
    assert_eq!(state.get_account_by_id(receiver_account_id).data.balance, 1);
}

#[test]
fn a_data_write_on_a_foreign_shard_is_rejected_publicly() {
    let target_id = AccountId::new([1; 32]);
    let other_id = AccountId::new([2; 32]);
    let mut state = V03State::new().with_test_programs();
    let program_id: AccountId = crate::test_methods::foreign_shard_writer().id().into();
    let foreign_program_account_id: AccountId = crate::test_methods::data_changer().id().into();

    let message = public_transaction::Message::try_new(
        program_id,
        vec![
            ProgramShardSelector::new(target_id, foreign_program_account_id),
            ProgramShardSelector::balance_only(other_id),
        ],
        vec![],
        vec![7_u8; 4],
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::ForeignShardWrite { account_id, executing_account_id }
        ))) if account_id == target_id && executing_account_id == program_id
    ));
}

#[test]
fn a_data_write_on_the_executing_shard_is_accepted_publicly() {
    let target_id = AccountId::new([1; 32]);
    let other_id = AccountId::new([2; 32]);
    let mut state = V03State::new().with_test_programs();
    let program_id: AccountId = crate::test_methods::foreign_shard_writer().id().into();
    let written = vec![7_u8; 4];

    let message = public_transaction::Message::try_new(
        program_id,
        vec![
            ProgramShardSelector::new(target_id, program_id),
            ProgramShardSelector::balance_only(other_id),
        ],
        vec![],
        written.clone(),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        state.get_account_by_id(target_id),
        Account::default().with_shard(program_id, written.try_into().unwrap())
    );
    assert_eq!(state.get_account_by_id(other_id), Account::default());
}

#[test]
fn program_should_fail_if_does_not_preserve_total_balance_by_minting() {
    let mut state = V03State::new().with_test_programs();
    let account_id = AccountId::new([1; 32]);
    let program_id: AccountId = crate::test_methods::minter().id().into();

    let message = public_transaction::Message::try_new(
        program_id,
        vec![ProgramShardSelector::balance_only(account_id)],
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
            ExecutionValidationError::MismatchedTotalBalance { total_added, total_subbed }
        ))) if total_added == 1.into() && total_subbed == 0.into()
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
    let program_id: AccountId = crate::test_methods::references_undeclared_account()
        .id()
        .into();
    let callee_id = crate::test_methods::noop().id();
    let instruction: (ProgramId, InstructionData, AccountId) = (
        callee_id,
        Program::serialize_instruction(()).unwrap(),
        undeclared_account_id,
    );
    let message = public_transaction::Message::try_new(
        program_id,
        vec![ProgramShardSelector::balance_only(account_id)],
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

/// Rejects a program output that includes an account absent from its inputs.
#[test]
fn program_should_fail_if_it_injects_an_undeclared_pre_state() {
    let account_id = AccountId::new([1; 32]);
    let fabricated_account_id = AccountId::new([123; 32]);
    let mut state = V03State::new()
        .with_public_account_balances([(account_id, 0)])
        .with_test_programs();
    let program_id: AccountId = crate::test_methods::injects_undeclared_pre_state()
        .id()
        .into();
    let message = public_transaction::Message::try_new(
        program_id,
        vec![ProgramShardSelector::balance_only(account_id)],
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
    let program_id: AccountId = crate::test_methods::burner().id().into();
    let key = PrivateKey::try_new([7; 32]).unwrap();
    let account_id = AccountId::from(&PublicKey::new_from_private_key(&key));
    let mut state = V03State::new()
        .with_public_account_balances([(account_id, 100)])
        .with_test_programs();
    let balance_to_burn: u128 = 1;
    assert!(state.get_account_by_id(account_id).data.balance > balance_to_burn);

    let message = public_transaction::Message::try_new(
        program_id,
        vec![ProgramShardSelector::balance_only(account_id)],
        vec![Nonce(0)],
        balance_to_burn,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&key]);
    let tx = PublicTransaction::new(message, witness_set);
    let result = state.transition_from_public_transaction(&tx, 2, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::ExecutionValidationFailed(
            ExecutionValidationError::MismatchedTotalBalance { total_added, total_subbed }
        ))) if total_added == 0.into() && total_subbed == 1.into()
    ));
}

/// Rejects a chained call that omits a requested shard selector from its output.
#[test]
fn program_should_fail_if_a_callee_drops_an_account_its_caller_named() {
    let owner = crate::test_methods::dropped_account().id();
    let mut state = V03State::new()
        .with_public_account_balances([
            (AccountId::new([1; 32]), 100),
            (AccountId::new([2; 32]), 0),
        ])
        .with_test_programs();

    // The forwarder names both accounts for the callee; the callee journals only the first.
    let message = public_transaction::Message::try_new(
        crate::test_methods::non_delegating_forwarder().id().into(),
        vec![
            ProgramShardSelector::balance_only(AccountId::new([1; 32])),
            ProgramShardSelector::balance_only(AccountId::new([2; 32])),
        ],
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
                InvalidProgramBehaviorError::ChainedCallAccountsMismatch { program_account_id }
            )) if program_account_id == AccountId::from(owner)
        ),
        "expected ChainedCallAccountsMismatch for the callee, got {result:?}"
    );
}

#[test]
fn insufficient_balance_transfer_leaves_state_untouched() {
    let program = crate::test_methods::simple_balance_transfer();
    let from_key = PrivateKey::try_new([21; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let initial_balance = 10;
    let mut state = V03State::new()
        .with_public_account_balances([(from, initial_balance)])
        .with_test_programs();

    let to_key = PrivateKey::try_new([22; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));
    let amount: u128 = initial_balance + 1;

    let sender_pre = state.get_account_by_id(from);
    let recipient_pre = state.get_account_by_id(to);

    let message = public_transaction::Message::try_new(
        program.id().into(),
        vec![
            ProgramShardSelector::balance_only(from),
            ProgramShardSelector::balance_only(to),
        ],
        vec![Nonce(0), Nonce(0)],
        amount,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&from_key, &to_key]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::ExecutionValidationFailed(
                ExecutionValidationError::InvalidBalanceDiff { account_id, .. }
            )
        )) if account_id == from
    ));

    assert_eq!(state.get_account_by_id(from), sender_pre);
    assert_eq!(state.get_account_by_id(to), recipient_pre);
}

/// Order no longer carries meaning: each `AccountStateDiff` embeds its own pre-state, so a
/// program listing its diffs in a different order than it received the corresponding pre-states
/// still validates and applies correctly.
#[test]
fn reordered_state_diffs_still_succeed() {
    let program = crate::test_methods::reordering_transfer();
    let from_key = PrivateKey::try_new([23; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let initial_balance = 10;
    let mut state = V03State::new()
        .with_public_account_balances([(from, initial_balance)])
        .with_test_programs();

    let to_key = PrivateKey::try_new([24; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));
    let amount: u128 = 4;

    let message = public_transaction::Message::try_new(
        program.id().into(),
        vec![
            ProgramShardSelector::balance_only(from),
            ProgramShardSelector::balance_only(to),
        ],
        vec![Nonce(0), Nonce(0)],
        amount,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&from_key, &to_key]);
    let tx = PublicTransaction::new(message, witness_set);

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        state.get_account_by_id(from).data.balance,
        initial_balance - amount
    );
    assert_eq!(state.get_account_by_id(to).data.balance, amount);
}

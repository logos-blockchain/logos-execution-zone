use super::*;

fn native_transfer_tx(
    sender: AccountId,
    receiver: AccountId,
    nonces: Vec<Nonce>,
    amount: u128,
    signers: &[&PrivateKey],
) -> PublicTransaction {
    let from = Actor::native_balance(sender);
    let to = Actor::native_balance(receiver);
    public_tx(
        from,
        vec![from, to],
        nonces,
        transfer(receiver, amount),
        signers,
    )
}

#[test]
fn program_should_fail_if_it_debits_an_unauthorized_account() {
    let sender_account_id = AccountId::new([1; 32]);
    let receiver_account_id = AccountId::new([2; 32]);
    let mut state = V03State::new().with_public_account_balances([(sender_account_id, 100)]);
    let tx = native_transfer_tx(sender_account_id, receiver_account_id, vec![], 1, &[]);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::NativeTransferFailed(
                TransferError::UnauthorizedSender {
                    account_id: err_account_id
                }
            )
        )) if err_account_id == sender_account_id
    ));
}

#[test]
fn program_should_transfer_balance_from_an_authorized_account() {
    let sender_key = PrivateKey::try_new([3; 32]).unwrap();
    let sender_account_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
    let receiver_account_id = AccountId::new([2; 32]);
    let mut state = V03State::new()
        .with_public_account_balances([(sender_account_id, 100), (receiver_account_id, 0)]);
    let tx = native_transfer_tx(
        sender_account_id,
        receiver_account_id,
        vec![Nonce(0)],
        1,
        &[&sender_key],
    );

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        state
            .get_account_by_id(sender_account_id)
            .data
            .native_balance(),
        Ok(99)
    );
    assert_eq!(
        state
            .get_account_by_id(receiver_account_id)
            .data
            .native_balance(),
        Ok(1)
    );
}

#[test]
fn a_data_write_on_the_executing_shard_is_accepted_publicly() {
    let target_id = AccountId::new([1; 32]);
    let mut state = V03State::new()
        .with_public_accounts([(target_id, Account::funded(250))])
        .with_programs([crate::test_methods::scripted()]);
    let program_id = scripted_id();
    let written = vec![7_u8; 4];

    let writer = Actor::new(target_id, program_id);
    let tx = public_tx(
        writer,
        vec![writer],
        vec![],
        Script::write(written.clone()),
        &[],
    );

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    // Funded beforehand, so the whole-account assertion also pins that an application write
    // leaves the native balance shard alone.
    assert_eq!(
        state.get_account_by_id(target_id),
        Account::funded(250).with_shard(program_id, written.try_into().unwrap())
    );
}

/// A send may only name an actor the transaction declared — never an arbitrary account that
/// merely exists (or not) in global state.
#[test]
fn program_should_fail_if_it_references_an_undeclared_account() {
    let account_id = AccountId::new([1; 32]);
    let undeclared_account_id = AccountId::new([99; 32]);
    let undeclared = Actor::new(undeclared_account_id, scripted_id());
    // Existing in global state does not make an undeclared account reachable.
    for balances in [
        vec![(account_id, 0)],
        vec![(account_id, 0), (undeclared_account_id, 99)],
    ] {
        let mut state = V03State::new()
            .with_public_account_balances(balances)
            .with_programs([crate::test_methods::scripted()]);
        let sender = Actor::new(account_id, scripted_id());
        let tx = public_tx(
            sender,
            vec![sender],
            vec![],
            Script::default().call(undeclared, &Script::default()),
            &[],
        );

        let result = state.transition_from_public_transaction(&tx, 1, 0);

        assert!(
            matches!(
                result,
                Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::Execution(
                    ExecutionError::UndeclaredActor { actor }
                ))) if actor == undeclared
            ),
            "expected UndeclaredActor for the undeclared actor, got {result:?}"
        );
    }
}

#[test]
fn program_should_fail_if_it_forges_its_pre_state() {
    let account_id = AccountId::new([1; 32]);
    let program_id = AccountId::from_builtin_program(crate::test_methods::forges_echo().id());
    let mut state = V03State::new()
        .with_public_account_balances([(account_id, 0)])
        .with_programs([crate::test_methods::forges_echo()]);
    let forger = Actor::new(account_id, program_id);
    let tx = public_tx(forger, vec![forger], vec![], ForgeField::PreState, &[]);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(
        matches!(
            &result,
            Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::Execution(
                ExecutionError::ExecutionValidation {
                    program_account_id: err_program_id,
                    source: ExecutionValidationError::TransitionInputMismatch { expected, actual },
                }
            ))) if *err_program_id == program_id
                && expected.pre_state.is_empty()
                && actual.pre_state.as_ref() == b"forged"
        ),
        "expected a transition input mismatch for the forged pre-data, got {result:?}"
    );
}

#[test]
fn insufficient_balance_transfer_leaves_state_untouched() {
    let from_key = PrivateKey::try_new([21; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let initial_balance = 10;
    let mut state = V03State::new().with_public_account_balances([(from, initial_balance)]);

    let to_key = PrivateKey::try_new([22; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));
    let amount: u128 = initial_balance + 1;

    let sender_pre = state.get_account_by_id(from);
    let recipient_pre = state.get_account_by_id(to);

    let tx = native_transfer_tx(
        from,
        to,
        vec![Nonce(0), Nonce(0)],
        amount,
        &[&from_key, &to_key],
    );

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    assert!(matches!(
        result,
        Err(LeeError::InvalidProgramBehavior(
            InvalidProgramBehaviorError::NativeTransferFailed(
                TransferError::InsufficientBalance { account_id }
            )
        )) if account_id == from
    ));

    assert_eq!(state.get_account_by_id(from), sender_pre);
    assert_eq!(state.get_account_by_id(to), recipient_pre);
}

#[test]
fn a_sent_turn_on_another_shard_of_the_root_account_keeps_its_other_shards() {
    let account_id = AccountId::new([1; 32]);
    let stranger = AccountId::new([9; 32]);
    let on_chain: ActorState = b"on-chain".to_vec().try_into().unwrap();
    let stranger_data: ActorState = b"stranger".to_vec().try_into().unwrap();
    let written = vec![7; 4];
    let mut state = V03State::new()
        .with_public_accounts([(
            account_id,
            Account {
                nonce: Nonce(3),
                ..Account::funded(5)
                    .with_shard(TWIN, on_chain)
                    .with_shard(stranger, stranger_data.clone())
            },
        )])
        .with_test_programs();

    let sender = Actor::new(account_id, scripted_id());
    let callee = Actor::new(account_id, TWIN);
    let tx = public_tx(
        sender,
        vec![sender, callee],
        vec![],
        Script::default().call(callee, &Script::write(written.clone())),
        &[],
    );

    state.transition_from_public_transaction(&tx, 1, 0).unwrap();

    assert_eq!(
        state.get_account_by_id(account_id),
        Account {
            nonce: Nonce(3),
            ..Account::funded(5)
                .with_shard(TWIN, written.try_into().unwrap())
                .with_shard(stranger, stranger_data)
        }
    );
}

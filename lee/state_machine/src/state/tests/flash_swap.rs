use super::*;

#[test]
fn flash_swap_successful() {
    let initiator = crate::test_methods::flash_swap_initiator();
    let callback = crate::test_methods::flash_swap_callback();
    let token = crate::test_methods::simple_balance_transfer();

    let vault_id = AccountId::for_public_pda(&initiator.id(), &PdaSeed::new([0_u8; 32]));
    let receiver_id = AccountId::for_public_pda(&callback.id(), &PdaSeed::new([1_u8; 32]));

    let initial_balance: u128 = 1000;
    let amount_out: u128 = 100;

    let vault_account = Account::single(
        token.id(),
        initial_balance,
        Data::default(),
        Nonce::default(),
    );
    let receiver_account = Account::single(token.id(), 0, Data::default(), Nonce::default());

    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(vault_id, vault_account);
    state.force_insert_account(receiver_id, receiver_account);

    // Callback instruction: return funds
    let cb_instruction = CallbackInstruction {
        return_funds: true,
        token_program_id: token.id(),
        amount: amount_out,
    };
    let cb_data = Program::serialize_instruction(cb_instruction).unwrap();

    let instruction = FlashSwapInstruction::Initiate {
        token_program_id: token.id(),
        callback_program_id: callback.id(),
        amount_out,
        callback_instruction_data: cb_data,
    };

    let tx = build_flash_swap_tx(&initiator, vault_id, receiver_id, instruction);
    let result = state.transition_from_public_transaction(&tx, 1, 0);
    assert!(result.is_ok(), "flash swap should succeed: {result:?}");

    // Vault balance restored, receiver back to 0
    assert_eq!(
        state.get_account_by_id(vault_id).balance(token.id()),
        initial_balance
    );
    assert_eq!(state.get_account_by_id(receiver_id).balance(token.id()), 0);
}

#[test]
fn flash_swap_callback_keeps_funds_rollback() {
    let initiator = crate::test_methods::flash_swap_initiator();
    let callback = crate::test_methods::flash_swap_callback();
    let token = crate::test_methods::simple_balance_transfer();

    let vault_id = AccountId::for_public_pda(&initiator.id(), &PdaSeed::new([0_u8; 32]));
    let receiver_id = AccountId::for_public_pda(&callback.id(), &PdaSeed::new([1_u8; 32]));

    let initial_balance: u128 = 1000;
    let amount_out: u128 = 100;

    let vault_account = Account::single(
        token.id(),
        initial_balance,
        Data::default(),
        Nonce::default(),
    );
    let receiver_account = Account::single(token.id(), 0, Data::default(), Nonce::default());

    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(vault_id, vault_account);
    state.force_insert_account(receiver_id, receiver_account);

    // Callback instruction: do NOT return funds
    let cb_instruction = CallbackInstruction {
        return_funds: false,
        token_program_id: token.id(),
        amount: amount_out,
    };
    let cb_data = Program::serialize_instruction(cb_instruction).unwrap();

    let instruction = FlashSwapInstruction::Initiate {
        token_program_id: token.id(),
        callback_program_id: callback.id(),
        amount_out,
        callback_instruction_data: cb_data,
    };

    let tx = build_flash_swap_tx(&initiator, vault_id, receiver_id, instruction);
    let result = state.transition_from_public_transaction(&tx, 1, 0);

    // Invariant check fails → entire tx rolls back
    assert!(
        result.is_err(),
        "flash swap should fail when callback keeps funds"
    );

    // State unchanged (rollback)
    assert_eq!(
        state.get_account_by_id(vault_id).balance(token.id()),
        initial_balance
    );
    assert_eq!(state.get_account_by_id(receiver_id).balance(token.id()), 0);
}

#[test]
fn flash_swap_self_call_targets_correct_program() {
    // Zero-amount flash swap: the invariant self-call still runs and succeeds
    // because vault balance doesn't decrease.
    let initiator = crate::test_methods::flash_swap_initiator();
    let callback = crate::test_methods::flash_swap_callback();
    let token = crate::test_methods::simple_balance_transfer();

    let vault_id = AccountId::for_public_pda(&initiator.id(), &PdaSeed::new([0_u8; 32]));
    let receiver_id = AccountId::for_public_pda(&callback.id(), &PdaSeed::new([1_u8; 32]));

    let initial_balance: u128 = 1000;

    let vault_account = Account::single(
        token.id(),
        initial_balance,
        Data::default(),
        Nonce::default(),
    );
    let receiver_account = Account::single(token.id(), 0, Data::default(), Nonce::default());

    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(vault_id, vault_account);
    state.force_insert_account(receiver_id, receiver_account);

    let cb_instruction = CallbackInstruction {
        return_funds: true,
        token_program_id: token.id(),
        amount: 0,
    };
    let cb_data = Program::serialize_instruction(cb_instruction).unwrap();

    let instruction = FlashSwapInstruction::Initiate {
        token_program_id: token.id(),
        callback_program_id: callback.id(),
        amount_out: 0,
        callback_instruction_data: cb_data,
    };

    let tx = build_flash_swap_tx(&initiator, vault_id, receiver_id, instruction);
    let result = state.transition_from_public_transaction(&tx, 1, 0);
    assert!(
        result.is_ok(),
        "zero-amount flash swap should succeed: {result:?}"
    );
}

#[test]
fn flash_swap_standalone_invariant_check_rejected() {
    // Calling InvariantCheck directly (not as a chained self-call) should fail
    // because caller_program_id will be None.
    let initiator = crate::test_methods::flash_swap_initiator();
    let token = crate::test_methods::simple_balance_transfer();

    let vault_id = AccountId::for_public_pda(&initiator.id(), &PdaSeed::new([0_u8; 32]));

    let vault_account = Account::single(token.id(), 1000, Data::default(), Nonce::default());

    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(vault_id, vault_account);

    // The vault invariant itself holds, so only the caller check can reject this.
    let instruction = FlashSwapInstruction::InvariantCheck {
        token_program_id: token.id(),
        min_vault_balance: 1000,
    };

    let message = public_transaction::Message::try_new(
        initiator.id(),
        slots_of(token.id(), &[vault_id]),
        vec![],
        instruction,
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);
    assert!(
        result.is_err(),
        "standalone InvariantCheck should be rejected (caller_program_id is None)"
    );
}

#[test]
fn malicious_self_program_id_rejected_in_public_execution() {
    let program = crate::test_methods::malicious_self_program_id();
    let acc_id = AccountId::new([99; 32]);
    let account = Account::default();

    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(acc_id, account);

    let message = public_transaction::Message::try_new(
        program.id(),
        slots_of(program.id(), &[acc_id]),
        vec![],
        (),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);
    assert!(
        result.is_err(),
        "program with wrong self_program_id in output should be rejected"
    );
}

#[test]
fn malicious_caller_program_id_rejected_in_public_execution() {
    let program = crate::test_methods::malicious_caller_program_id();
    let acc_id = AccountId::new([99; 32]);
    let account = Account::default();

    let mut state = V03State::new().with_test_programs();
    state.force_insert_account(acc_id, account);

    let message = public_transaction::Message::try_new(
        program.id(),
        slots_of(program.id(), &[acc_id]),
        vec![],
        (),
    )
    .unwrap();
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);
    assert!(
        result.is_err(),
        "program with spoofed caller_program_id in output should be rejected"
    );
}

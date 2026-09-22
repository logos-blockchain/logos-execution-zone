use borsh::BorshDeserialize as _;
use lee_core::{
    account::{AccountId, BalanceDiff, ShardData},
    program::{AccountInput, AccountStateDiff, CallKind, ProgramInput, UnsupportedCallKind},
    to_borsh_frame, to_frame,
};
use risc0_zkvm::{ExecutorEnv, default_executor};

use crate::{
    error::{InvalidProgramBehaviorError, LeeError},
    program::{DEFAULT_PUBLIC_CYCLE_BUDGET, Program, check_input_rows},
};

fn transfer_fixture() -> (Program, Vec<AccountInput>, Vec<u8>, u128) {
    let program = crate::test_methods::simple_balance_transfer();
    let balance_to_move: u128 = 11_223_344_556_677;
    let instruction_data = Program::serialize_instruction(balance_to_move).unwrap();
    let sender = AccountInput::balance(AccountId::new([0; 32]), true, 77_665_544_332_211);
    let recipient = AccountInput::balance(AccountId::new([1; 32]), false, 0);
    (
        program,
        vec![sender, recipient],
        instruction_data,
        balance_to_move,
    )
}

#[test]
fn program_execution() {
    let (program, pre_states, instruction_data, balance_to_move) = transfer_fixture();

    let (program_output, _cycles) = program
        .execute(
            AccountId::from_builtin_program(program.id()),
            None,
            &pre_states,
            &instruction_data,
            DEFAULT_PUBLIC_CYCLE_BUDGET,
        )
        .unwrap();

    let [sender_post, recipient_post] = program_output.state_diffs.try_into().unwrap();

    assert_eq!(
        sender_post.post_balance_diff,
        BalanceDiff::Sub(balance_to_move)
    );
    assert_eq!(sender_post.post_data, None);
    assert_eq!(
        recipient_post.post_balance_diff,
        BalanceDiff::Add(balance_to_move)
    );
    assert_eq!(recipient_post.post_data, None);
}

#[test]
fn journal_is_the_borsh_frame_of_the_output_and_echoes_instruction_data() {
    let program = crate::test_methods::simple_balance_transfer();
    let instruction_data = Program::serialize_instruction(7_u128).unwrap();
    let pre_states = [
        AccountInput::balance(AccountId::new([0; 32]), true, 10),
        AccountInput::balance(AccountId::new([1; 32]), false, 0),
    ];

    let mut env_builder = ExecutorEnv::builder();
    program
        .write_inputs(
            AccountId::from_builtin_program(program.id()),
            None,
            &pre_states,
            &instruction_data,
            &mut env_builder,
        )
        .unwrap();
    let session_info = default_executor()
        .execute(env_builder.build().unwrap(), program.elf())
        .unwrap();

    let payload = lee_core::from_frame(&session_info.journal.bytes).unwrap();
    let output: lee_core::program::ProgramOutput = borsh::from_slice(payload).unwrap();

    // The journal must be byte-identical to `to_frame(borsh(output))`: the privacy circuit
    // reconstructs exactly these bytes for `env::verify`, so any drift breaks recursion.
    assert_eq!(
        session_info.journal.bytes,
        lee_core::to_frame(&borsh::to_vec(&output).unwrap())
    );
    // The guest must echo the instruction bytes verbatim: chained-call binding compares them.
    assert_eq!(output.instruction_data, instruction_data);
}

#[test]
fn malformed_journal_frame_is_an_error_not_a_panic() {
    let program = crate::test_methods::malformed_journal();
    let err = program
        .execute(
            AccountId::from_builtin_program(program.id()),
            None,
            &[],
            &Vec::new(),
            DEFAULT_PUBLIC_CYCLE_BUDGET,
        )
        .unwrap_err();
    assert!(
        matches!(
            &err,
            crate::error::LeeError::ProgramExecutionFailed(msg)
                if msg.contains("malformed program journal frame")
        ),
        "expected malformed-frame ProgramExecutionFailed, got: {err:?}"
    );
}

#[test]
fn execute_reports_cycles_within_budget() {
    let (program, pre_states, instruction_data, _) = transfer_fixture();
    let (_, cycles) = program
        .execute(
            AccountId::from_builtin_program(program.id()),
            None,
            &pre_states,
            &instruction_data,
            DEFAULT_PUBLIC_CYCLE_BUDGET,
        )
        .expect("executes");
    assert!(cycles > 0);
    // Holds because this transfer costs far less than the budget; not a general
    // invariant — a session can overshoot its limit by up to one instruction.
    assert!(cycles <= DEFAULT_PUBLIC_CYCLE_BUDGET);
}

#[test]
fn tiny_budget_is_out_of_gas() {
    let (program, pre_states, instruction_data, _) = transfer_fixture();
    let result = program.execute(
        AccountId::from_builtin_program(program.id()),
        None,
        &pre_states,
        &instruction_data,
        1_024,
    );
    assert!(matches!(result, Err(LeeError::OutOfGas { budget: 1_024 })));
}

/// An unmodified guest succeeds with a no-op when invoked with a call kind it was never
/// compiled to understand, rather than failing. Crafts the invocation by hand to simulate what
/// a future call kind looks like to a guest built before it existed.
#[test]
fn program_survives_a_call_kind_it_does_not_recognize() {
    let program = crate::test_methods::simple_balance_transfer();
    let instruction_data = Program::serialize_instruction(7_u128).unwrap();
    let pre_states = vec![
        AccountInput::balance(AccountId::new([0; 32]), true, 10),
        AccountInput::balance(AccountId::new([1; 32]), false, 0),
    ];

    let mut env_builder = ExecutorEnv::builder();
    // Stands in for a call kind a future protocol upgrade defines.
    env_builder.write_slice(&to_borsh_frame(&CallKind::Unknown(77)));
    let input = ProgramInput {
        self_account_id: AccountId::from_builtin_program(program.id()),
        caller_account_id: None,
        pre_states: pre_states.clone(),
        instruction: instruction_data.clone(),
    };
    env_builder.write_slice(&to_frame(&borsh::to_vec(&input).unwrap()));

    let session_info = default_executor()
        .execute(env_builder.build().unwrap(), program.elf())
        .expect("an unrecognized call kind must not fail guest execution");

    let payload = lee_core::from_frame(&session_info.journal.bytes).unwrap();
    let output: lee_core::program::ProgramOutput = borsh::from_slice(payload).unwrap();

    assert_eq!(output.call_kind, CallKind::Unknown(77));

    // A no-op, not the program's own transfer logic: every account comes back unchanged.
    assert_eq!(output.state_diffs.len(), pre_states.len());
    for diff in &output.state_diffs {
        assert_eq!(diff.post_balance_diff, BalanceDiff::Add(0));
        assert_eq!(diff.post_data, None);
    }
    assert!(output.chained_calls.is_empty());
    assert_eq!(output.instruction_data, instruction_data);

    // The skip is recorded, not silent.
    let event = output
        .events
        .iter()
        .find(|event| event.selector == UnsupportedCallKind::SELECTOR)
        .expect("an UnsupportedCallKind event must be emitted");
    let decoded = UnsupportedCallKind::try_from_slice(&event.data).unwrap();
    assert_eq!(decoded.raw_discriminant, 77);
}

/// A guest that halts with a non-zero code is rejected, but unlike a panic the session survives:
/// the error carries the metered cycles so the caller can charge them.
#[test]
fn nonzero_exit_is_rejected_with_its_cycles() {
    let program = crate::test_methods::exits_nonzero();
    let err = program
        .execute(
            AccountId::from_builtin_program(program.id()),
            None,
            &[],
            &Vec::new(),
            DEFAULT_PUBLIC_CYCLE_BUDGET,
        )
        .unwrap_err();
    assert!(
        matches!(err, LeeError::ProgramExitedWithCode { code: 3, cycles } if cycles > 0),
        "expected ProgramExitedWithCode {{ code: 3, cycles > 0 }}, got: {err:?}"
    );
}

#[test]
fn input_rows_must_be_returned_exactly() {
    let program_account_id = AccountId::new([9; 32]);
    let inputs = vec![
        AccountInput::with_shard(
            AccountId::new([1; 32]),
            true,
            5,
            program_account_id,
            ShardData::try_from(vec![1]).unwrap(),
        ),
        AccountInput::balance(AccountId::new([2; 32]), false, 0),
    ];
    let check = |rows: &[AccountInput]| {
        let diffs: Vec<_> = rows
            .iter()
            .cloned()
            .map(AccountStateDiff::unchanged)
            .collect();
        check_input_rows(program_account_id, &inputs, &diffs)
    };
    let tamperings: [fn(&mut Vec<AccountInput>); 7] = [
        |rows| rows.swap(0, 1),
        |rows| rows[0].is_authorized = false,
        |rows| rows[1].is_authorized = true,
        |rows| rows[0].balance = 6,
        |rows| rows[0].shard.as_mut().unwrap().0 = AccountId::new([8; 32]),
        |rows| rows[0].shard.as_mut().unwrap().1 = ShardData::empty(),
        |rows| rows[0].shard = None,
    ];

    assert!(check(&inputs).is_ok());
    for tamper in tamperings {
        let mut rows = inputs.clone();
        tamper(&mut rows);
        assert!(matches!(
            check(&rows),
            Err(InvalidProgramBehaviorError::InconsistentAccountPreState { .. })
        ));
    }
    let extended = [inputs.as_slice(), &inputs[1..]].concat();
    for rows in [&inputs[..1], extended.as_slice()] {
        assert!(matches!(
            check(rows),
            Err(InvalidProgramBehaviorError::InputRowsMismatch { .. })
        ));
    }
}

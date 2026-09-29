use lee_core::{
    account::{AccountId, Actor, ShardData},
    program::{Origin, ReceiveInput},
};
use test_guest_core::Script;

use crate::{
    error::LeeError,
    program::{DEFAULT_PUBLIC_CYCLE_BUDGET, Program},
};

fn receive_input(program: &Program, message: Vec<u8>) -> ReceiveInput {
    let receiver = Actor::new(
        AccountId::new([0; 32]),
        AccountId::from_builtin_program(program.id()),
    );
    ReceiveInput {
        receiver,
        origin: Origin::Root,
        is_authorized: true,
        pre_data: ShardData::empty(),
        message,
    }
}

fn write_fixture() -> (Program, ReceiveInput, Vec<u8>) {
    let program = crate::test_methods::scripted();
    let written = vec![7_u8; 4];
    let message = Program::serialize_message(Script::write(written.clone())).unwrap();
    let input = receive_input(&program, message);
    (program, input, written)
}

#[test]
fn program_execution() {
    let (program, input, written) = write_fixture();

    let (transition, _cycles) = program
        .receive(&input, DEFAULT_PUBLIC_CYCLE_BUDGET)
        .unwrap();

    // The transition echoes the exact input it was handed — that echo is what the engine matches
    // against the delivery it scheduled.
    assert_eq!(transition.input, input);
    assert_eq!(transition.post_data, Some(written.try_into().unwrap()));
    assert!(transition.sends.is_empty());
}

#[test]
fn malformed_journal_frame_is_an_error_not_a_panic() {
    let program = crate::test_methods::malformed_journal();
    let err = program
        .receive(
            &receive_input(&program, Vec::new()),
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
    let (program, input, _) = write_fixture();
    let (_, cycles) = program
        .receive(&input, DEFAULT_PUBLIC_CYCLE_BUDGET)
        .expect("executes");
    assert!(cycles > 0);
    // Holds because this write costs far less than the budget; not a general
    // invariant — a session can overshoot its limit by up to one instruction.
    assert!(cycles <= DEFAULT_PUBLIC_CYCLE_BUDGET);
}

#[test]
fn tiny_budget_is_out_of_gas() {
    let (program, input, _) = write_fixture();
    let result = program.receive(&input, 1_024);
    assert!(matches!(result, Err(LeeError::OutOfGas { budget: 1_024 })));
}

/// A guest that halts with a non-zero code is rejected, but unlike a panic the session survives:
/// the error carries the metered cycles so the caller can charge them.
#[test]
fn nonzero_exit_is_rejected_with_its_cycles() {
    let program = crate::test_methods::exits_nonzero();
    let err = program
        .receive(
            &receive_input(&program, Vec::new()),
            DEFAULT_PUBLIC_CYCLE_BUDGET,
        )
        .unwrap_err();
    assert!(
        matches!(err, LeeError::ProgramExitedWithCode { code: 3, cycles } if cycles > 0),
        "expected ProgramExitedWithCode {{ code: 3, cycles > 0 }}, got: {err:?}"
    );
}

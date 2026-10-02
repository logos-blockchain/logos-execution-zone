use lee_core::{
    account::{AccountId, Actor, ActorState},
    program::{ReceiveInput, Transition},
    to_frame,
};
use risc0_zkvm::{ExecutorEnv, default_executor};
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
        origin: None,
        is_authorized: true,
        pre_state: ActorState::empty(),
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
    assert_eq!(transition.response.post_state, Some(written.into()));
    assert!(transition.response.calls.is_empty() && transition.response.casts.is_empty());
}

#[test]
fn journal_is_the_borsh_frame_of_the_transition_and_echoes_the_message() {
    let (program, input, _) = write_fixture();

    let mut env_builder = ExecutorEnv::builder();
    Program::write_receive_input(&input, &mut env_builder).unwrap();
    let session_info = default_executor()
        .execute(env_builder.build().unwrap(), program.elf())
        .unwrap();

    let payload = lee_core::from_frame(&session_info.journal.bytes).unwrap();
    let transition: Transition = borsh::from_slice(payload).unwrap();

    // The journal must be byte-identical to `to_frame(borsh(transition))`: the privacy circuit
    // reconstructs exactly these bytes for `env::verify`, so any drift breaks recursion.
    assert_eq!(
        session_info.journal.bytes,
        lee_core::to_frame(&borsh::to_vec(&transition).unwrap())
    );
    // The guest must echo the message bytes verbatim: delivery binding compares them.
    assert_eq!(transition.input.message, input.message);
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

/// There is no capability probe in this model: a guest handed an input it cannot decode must
/// fail rather than answer with a no-op that would count as success.
#[test]
fn an_undecodable_input_fails_the_guest() {
    let (program, _, _) = write_fixture();

    let mut env_builder = ExecutorEnv::builder();
    env_builder.write_slice(&to_frame(&[77_u8]));

    let err = default_executor()
        .execute(env_builder.build().unwrap(), program.elf())
        .expect_err("an undecodable input must fail guest execution");

    assert!(
        format!("{err:#}").contains("receive input must be valid borsh"),
        "expected an input decode failure, got: {err:#}"
    );
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

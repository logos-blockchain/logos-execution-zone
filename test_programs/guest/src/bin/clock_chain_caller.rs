use borsh::to_vec;
use lee_core::{
    Timestamp,
    account::AccountDiff,
    program::{
        AccountDiffOutput, ChainedCall, ProgramCall, ProgramId, ProgramInput, ProgramOutput,
        read_lee_call,
    },
};

type Instruction = (ProgramId, Timestamp); // (clock_program_id, timestamp)

/// A program that chain-calls the clock program with the clock accounts it received as pre-states.
/// Used in tests to verify that user transactions cannot modify clock accounts, even indirectly
/// via chain calls.
fn main() {
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (clock_program_id, timestamp),
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let post_states: Vec<_> = pre_states
        .iter()
        .map(|pre| AccountDiffOutput::new(AccountDiff::unchanged(pre.account_id)))
        .collect();

    let chained_call = ChainedCall {
        program_id: clock_program_id,
        instruction_data: to_vec(&timestamp).unwrap(),
        pre_states: pre_states.clone(),
        pda_seeds: vec![],
    };

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .with_chained_calls(vec![chained_call])
    .write();
}

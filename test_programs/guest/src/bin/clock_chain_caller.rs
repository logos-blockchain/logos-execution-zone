use borsh::to_vec;
use lee_core::{
    Timestamp,
    account::Position,
    program::{
        ChainedCall, ProgramCall, ProgramId, ProgramInput, ProgramOutput, ShardStateDiff,
        read_lee_call, respond_unsupported_call,
    },
};

type Instruction = (ProgramId, Timestamp); // (clock_program_id, timestamp)

/// A program that chain-calls the clock program with the clock accounts it received as pre-states.
/// Used in tests to verify that user transactions cannot modify clock accounts, even indirectly
/// via chain calls.
fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (clock_program_id, timestamp),
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    let state_diffs: Vec<_> = pre_states
        .iter()
        .map(|pre| ShardStateDiff::unchanged(pre.clone()))
        .collect();

    let chained_call = ChainedCall {
        program_account_id: clock_program_id.into(),
        instruction_data: to_vec(&timestamp).unwrap(),
        positions: pre_states.iter().map(Position::from).collect(),
        pda_seeds: vec![],
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        state_diffs,
    )
    .with_chained_calls(vec![chained_call])
    .write();
}

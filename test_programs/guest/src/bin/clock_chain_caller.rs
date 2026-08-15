use borsh::to_vec;
use lee_core::{
    Timestamp,
    account::AccountId,
    program::{AccountPostState, ChainedCall, ProgramInput, ProgramOutput, read_lee_inputs},
};

type Instruction = (AccountId, Timestamp); // (clock_program_id, timestamp)

/// A program that chain-calls the clock program with the clock accounts it received as pre-states.
/// Used in tests to verify that user transactions cannot modify clock accounts, even indirectly
/// via chain calls.
fn main() {
    let (
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction: (clock_program_id, timestamp),
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    let post_states: Vec<_> = pre_states
        .iter()
        .map(|pre| AccountPostState::new(pre.account.clone()))
        .collect();

    let chained_call = ChainedCall {
        program_account_id: clock_program_id,
        instruction_data: to_vec(&timestamp).unwrap(),
        pre_states: pre_states.clone(),
        pda_seeds: vec![],
        raw_payload: None,
    };

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        pre_states,
        post_states,
    )
    .with_chained_calls(vec![chained_call])
    .write();
}

use lee_core::{
    Timestamp,
    account::{AccountDiff, BalanceDiff},
    program::{
        AccountDiffOutput, ChainedCall, ProgramCall, ProgramId, ProgramInput, ProgramOutput,
        read_lee_call,
    },
};
use risc0_zkvm::serde::to_vec;

type Instruction = (ProgramId, Timestamp); // (clock_program_id, timestamp)

/// A program that chain-calls the clock program with the clock accounts it received as pre-states.
/// Used in tests to verify that user transactions cannot modify clock accounts, even indirectly
/// via chain calls.
fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: (clock_program_id, timestamp),
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff { .. } => unreachable!(
            "clock_chain_caller program never writes diff_data, so update_from_diff is never dispatched"
        ),
    };

    let post_states: Vec<_> = pre_states
        .iter()
        .map(|pre| {
            AccountDiffOutput::new(AccountDiff {
                id: pre.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: None,
            })
        })
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
        instruction_words,
        pre_states,
        post_states,
    )
    .with_chained_calls(vec![chained_call])
    .write();
}

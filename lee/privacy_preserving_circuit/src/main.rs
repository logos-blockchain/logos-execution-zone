use lee_core::{
    PrivacyPreservingCircuitInput,
    program::{ChainedCall, read_input_frame},
};
use risc0_zkvm::guest::env;

mod execution_state;
mod output;

fn main() {
    let PrivacyPreservingCircuitInput {
        program_effects,
        top_level_program_id,
        top_level_instruction_data,
        top_level_accounts,
        input_accounts,
        dummy_inputs,
    } = borsh::from_slice(&read_input_frame()).expect("circuit input must be valid borsh");

    let input_accounts = execution_state::index_by_account_id(input_accounts);

    let execution_state = execution_state::ExecutionState::derive(
        &input_accounts,
        program_effects,
        ChainedCall {
            program_id: top_level_program_id,
            instruction_data: top_level_instruction_data,
            accounts: top_level_accounts,
            pda_seeds: Vec::new(),
        },
    );

    let output = output::compute_circuit_output(execution_state, &input_accounts, dummy_inputs);

    env::commit_slice(&lee_core::to_borsh_frame(&output));
}

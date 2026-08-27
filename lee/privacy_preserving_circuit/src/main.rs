use lee_core::{PrivacyPreservingCircuitInput, program::read_input_frame};
use risc0_zkvm::guest::env;

mod execution_state;
mod output;

fn main() {
    let PrivacyPreservingCircuitInput {
        program_outputs,
        top_level_pre_state_refs,
        input_accounts,
        program_id,
        dummy_inputs,
    } = borsh::from_slice(&read_input_frame()).expect("circuit input must be valid borsh");

    let input_accounts = execution_state::index_by_account_id(input_accounts);

    let execution_state = execution_state::ExecutionState::derive_from_outputs(
        &input_accounts,
        program_id,
        program_outputs,
        top_level_pre_state_refs,
    );

    let output = output::compute_circuit_output(execution_state, &input_accounts, dummy_inputs);

    env::commit_slice(&lee_core::to_borsh_frame(&output));
}

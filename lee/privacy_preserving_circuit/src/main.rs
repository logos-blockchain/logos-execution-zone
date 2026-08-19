use lee_core::{PrivacyPreservingCircuitInput, program::read_input_frame};
use risc0_zkvm::guest::env;

mod execution_state;
mod output;

fn main() {
    let PrivacyPreservingCircuitInput {
        program_outputs,
        account_identities,
        program_id,
        dummy_inputs,
    } = borsh::from_slice(&read_input_frame()).expect("circuit input must be a valid borsh frame");

    let execution_state = execution_state::ExecutionState::derive_from_outputs(
        &account_identities,
        program_id,
        program_outputs,
    );

    let output = output::compute_circuit_output(execution_state, &account_identities, dummy_inputs);

    let payload = borsh::to_vec(&output).expect("borsh serialization is infallible");
    env::commit_slice(&lee_core::to_frame(&payload));
}

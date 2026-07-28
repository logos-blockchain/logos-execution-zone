use lee_core::{PrivacyPreservingCircuitInput, program::ChainedCall, validate_state_diff};
use risc0_zkvm::guest::env;

mod output;
mod private_backend;

fn main() {
    let PrivacyPreservingCircuitInput {
        program_outputs,
        private_rows,
        program_id,
    } = env::read();

    let initial_call = ChainedCall {
        program_id,
        instruction_data: program_outputs
            .first()
            .expect("No program outputs provided")
            .instruction_data
            .clone(),
        pre_states: Vec::new(),
        pda_seeds: Vec::new(),
    };
    let mut protocol_env = private_backend::PrivateBackend::new(private_rows, program_outputs);
    let threaded = validate_state_diff(&mut protocol_env, initial_call)
        .expect("private transaction validation failed");

    let output = output::compute_circuit_output(protocol_env, threaded);

    env::commit(&output);
}

use lee_core::PrivacyPreservingCircuitInput;
use risc0_zkvm::guest::env;

mod execution_state;
mod output;

fn main() {
    let PrivacyPreservingCircuitInput {
        program_outputs,
        account_identities,
        program_id,
        dummy_inputs,
        program_image_claims,
    } = env::read();

    let execution_state = execution_state::ExecutionState::derive_from_outputs(
        &account_identities,
        program_id,
        program_outputs,
        &program_image_claims,
    );

    let mut output =
        output::compute_circuit_output(execution_state, &account_identities, dummy_inputs);
    output.program_image_claims = program_image_claims;

    env::commit(&output);
}

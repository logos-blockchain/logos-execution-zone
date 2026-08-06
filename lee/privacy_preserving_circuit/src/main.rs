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
        exhibited_keys,
    } = env::read();

    let execution_state = execution_state::ExecutionState::derive_from_outputs(
        &account_identities,
        program_id,
        program_outputs,
        &exhibited_keys,
    );

    let output = output::compute_circuit_output(execution_state, &account_identities, dummy_inputs);

    env::commit(&output);
}

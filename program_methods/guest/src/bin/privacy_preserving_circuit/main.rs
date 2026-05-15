use nssa_core::PrivacyPreservingCircuitInput;
use risc0_zkvm::guest::env;

mod execution_state;
mod output;

fn main() {
    let PrivacyPreservingCircuitInput {
        program_outputs,
        account_identities,
        program_id,
    } = env::read();

    let execution_state = execution_state::ExecutionState::derive_from_outputs(
        &account_identities,
        program_id,
        program_outputs,
    );

    let output = output::compute_circuit_output(execution_state, &account_identities);

    env::commit(&output);
}

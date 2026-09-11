use lee_core::{PrivacyPreservingCircuitInput, ProgramImageWitness, program::read_input_frame};
use risc0_zkvm::guest::env;

mod execution_state;
mod output;

fn main() {
    let PrivacyPreservingCircuitInput {
        program_outputs,
        account_identities,
        program_account_id,
        dummy_inputs,
        initial_pre_states,
        program_image_witnesses,
        shadow_program_witnesses,
    } = borsh::from_slice(&read_input_frame()).expect("circuit input must be valid borsh");

    let execution_state = execution_state::ExecutionState::derive_from_outputs(
        &account_identities,
        program_account_id,
        program_outputs,
        &initial_pre_states,
        &program_image_witnesses,
        &shadow_program_witnesses,
    );

    // For `Private`, this is where the membership check itself happens.
    let program_image_claims = program_image_witnesses
        .iter()
        .map(ProgramImageWitness::to_claim)
        .collect();

    let output = output::compute_circuit_output(
        execution_state,
        &account_identities,
        dummy_inputs,
        program_image_claims,
    );

    env::commit_slice(&lee_core::to_borsh_frame(&output));
}

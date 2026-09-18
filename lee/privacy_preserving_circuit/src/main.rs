use lee_core::{
    PrivacyPreservingCircuitInput,
    program::{ChainedCall, read_input_frame},
    validation::{Declarations, validate_state_diff},
};
use risc0_zkvm::guest::env;

mod output;
mod private_backend;

fn main() {
    let PrivacyPreservingCircuitInput {
        program_outputs,
        account_identities,
        program_account_id,
        dummy_inputs,
        ciphertext_padding,
        initial_pre_states,
        program_image_claims,
    } = borsh::from_slice(&read_input_frame()).expect("circuit input must be valid borsh");

    let Some(first_output) = program_outputs.first() else {
        panic!("No program outputs provided");
    };
    // Only bootstraps the loop's first iteration: the top-level call has no caller to have named
    // its accounts, so `pre_state_ids` is never read for it.
    let initial_call = ChainedCall {
        program_account_id,
        instruction_data: first_output.instruction_data.clone(),
        pre_state_ids: first_output
            .state_diffs
            .iter()
            .map(|diff| diff.pre_state.account_id)
            .collect(),
        pda_seeds: Vec::new(),
    };
    let declarations = Declarations {
        must_be_touched: &initial_pre_states,
        // The top-level call is reached through a proof, not through a caller that named its
        // accounts, so there is no declaration confining its own output.
        root_output_is_confined: false,
    };

    let mut backend = private_backend::PrivateBackend::new(
        &account_identities,
        program_outputs,
        &program_image_claims,
    );
    let threaded = match validate_state_diff(&mut backend, initial_call, &declarations) {
        Ok(threaded) => threaded,
        // `Fatal` is uninhabited: every rejection already panicked at its own failure site.
        Err(fatal) => match fatal {},
    };
    let derived_outputs = backend.into_parts();

    let output = output::compute_circuit_output(
        threaded.accounts,
        &derived_outputs,
        &account_identities,
        dummy_inputs,
        ciphertext_padding,
        program_image_claims,
    );

    env::commit_slice(&lee_core::to_borsh_frame(&output));
}
